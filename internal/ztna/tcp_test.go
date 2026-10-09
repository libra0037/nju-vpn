package ztna

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/ztnatest"
)

func TestTCPConnectWithoutL3PreservesTargetsAndBufferedData(t *testing.T) {
	for _, tc := range []struct {
		name, host, dialIP string
		pretend            bool
	}{
		{"literal", "192.0.2.7", "", false}, {"domain", "db.example.edu", "", true}, {"supplied-ip", "db.example.edu", "198.51.100.8", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := ztnatest.App{ID: "app", NodeGroupID: "ng1", AccessModel: "L3VPN", Host: tc.host, Protocol: "tcp", Port: "443", AddrPretend: tc.pretend}
			if tc.dialIP != "" {
				app.IP = []string{tc.dialIP}
			}
			srv := newFake(t, ztnatest.Options{Apps: []ztnatest.App{app}, TCPGreeting: []byte("greeting"), TCPHandler: func(c net.Conn) {
				body, err := io.ReadAll(c)
				if err != nil {
					return
				}
				_, _ = c.Write(append([]byte("reply:"), body...))
				_ = c.(interface{ CloseWrite() error }).CloseWrite()
			}})
			client := newTestClient(t, srv, testPass)
			sess, err := client.Connect(t.Context(), ConnectOptions{})
			closeSessionAfterTest(t, sess)
			if err != nil {
				t.Fatal(err)
			}
			if sess.ClientIP() != nil || srv.Tunnels() != 0 {
				t.Fatal("L4 登录启动了 L3")
			}
			view, err := sess.Resources()
			if err != nil || view.IP == nil || view.TCPDomains == nil {
				t.Fatal("无 L3 时无法查询", err)
			}
			target, _ := NewTCPTarget(tc.host, 443)
			stream, err := sess.DialTCP(t.Context(), target)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			if err := stream.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			greeting := make([]byte, 8)
			if _, err := io.ReadFull(stream, greeting); err != nil || string(greeting) != "greeting" {
				t.Fatal("丢失预读字节", err)
			}
			if _, err := stream.Write([]byte("payload")); err != nil {
				t.Fatal(err)
			}
			if err := stream.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			reply, err := io.ReadAll(stream)
			if err != nil || string(reply) != "reply:payload" {
				t.Fatal("半关闭丢失反向响应", string(reply), err)
			}
			host, port := stream.BoundAddress()
			if host != "198.51.100.9" || port != 40000 {
				t.Fatal("绑定地址被节点地址替代", host, port)
			}
			requests := srv.TCPRequests()
			if len(requests) != 1 {
				t.Fatal("拨号次数错误", len(requests))
			}
			wantHost := tc.host
			if tc.dialIP != "" {
				wantHost = tc.dialIP
			}
			r := requests[0]
			if r.AppID != "app" || r.URL != "tcp://"+tc.host+":443" || r.DestAddr != tc.host+":443" || r.DestIP != tc.dialIP || r.Host != wantHost || r.Port != 443 {
				t.Fatal("L4 请求身份或目标错误", r)
			}
			if srv.Tunnels() != 0 {
				t.Fatal("L4 使用了 L3")
			}
		})
	}
}

func TestTCPReplyFixedBytesAndFailures(t *testing.T) {
	const auth = "\x05\x81\x53\x00\x00\x0a" + `{"code":0}`
	const bound = "\x05\x00\x00\x01\xc6\x33\x64\x09\x9c\x40"
	r := bufio.NewReader(strings.NewReader(auth + bound + "early"))
	host, port, err := readTCPReply(r)
	if err != nil || host != "198.51.100.9" || port != 40000 {
		t.Fatal("固定线上回复未识别", host, port, err)
	}
	body, _ := io.ReadAll(r)
	if string(body) != "early" {
		t.Fatal("读取回复吃掉业务字节")
	}
	for _, tc := range []struct {
		body  string
		gone  bool
		reply byte
	}{
		{"\x05\x81\x53\x00\x00\x11" + `{"code":75500002}`, true, 0},
		{auth + "\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00", false, 5},
		{auth + "\x05\x00\x01\x01\x00\x00\x00\x00\x00\x00", false, 0},
		{"\x05\x81\x53\x00\x00\x02{}", false, 0},
		{"\x05\x81\x53\x01\x00\x0a" + `{"code":0}`, false, 0},
	} {
		_, _, err := readTCPReply(strings.NewReader(tc.body))
		if err == nil {
			t.Fatal("非法或拒绝回复成功")
		}
		var gone *ErrSessionGone
		var rejected *TCPConnectError
		if errors.As(err, &gone) != tc.gone || tc.reply != 0 && (!errors.As(err, &rejected) || rejected.Reply != tc.reply) {
			t.Fatal("错误类别错误", err)
		}
	}
	for n := 0; n < len(auth+bound); n++ {
		if _, _, err := readTCPReply(bytes.NewReader([]byte(auth + bound)[:n])); err == nil {
			t.Fatal("截断握手成功", n)
		}
	}
}

func TestTCPRequestFixedLayoutAndIndependentSignature(t *testing.T) {
	srv := newFake(t, ztnatest.Options{})
	client := newTestClient(t, srv, testPass)
	sess, err := client.Connect(t.Context(), ConnectOptions{})
	closeSessionAfterTest(t, sess)
	if err != nil {
		t.Fatal(err)
	}
	sess.signKey = []byte("fixed-test-key") // 仅在尚无数据任务的离线会话修改。
	for _, tc := range []struct {
		host, ip string
		tail     []byte
	}{
		{"192.0.2.1", "", []byte{5, 1, 0, 1, 192, 0, 2, 1, 1, 187}},
		{"db.edu", "", []byte{5, 1, 0, 3, 6, 'd', 'b', '.', 'e', 'd', 'u', 1, 187}},
		{"db.edu", "198.51.100.1", []byte{5, 1, 0, 1, 198, 51, 100, 1, 1, 187}},
	} {
		target, _ := NewTCPTarget(tc.host, 443)
		route := tcpRoute{grant: resourceGrant{appID: "app"}, target: target}
		if tc.ip != "" {
			route.dialIPs = []netip.Addr{netip.MustParseAddr(tc.ip)}
		}
		request, err := sess.tcpRequest(route, 0)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(request[:5], []byte{5, 1, 0x81, 0x53, 3}) {
			t.Fatal("方法/模式不是固定字节")
		}
		n := int(binary.BigEndian.Uint16(request[5:7]))
		if !bytes.Equal(request[7+n:], tc.tail) {
			t.Fatal("目标帧字节错误")
		}
		var body map[string]any
		if err := json.Unmarshal(request[7:7+n], &body); err != nil {
			t.Fatal(err)
		}
		if body["appId"] != "app" || body["url"] != "tcp://"+tc.host+":443" || body["destAddr"] != tc.host+":443" {
			t.Fatal("目标身份错误")
		}
		if tc.ip == "" {
			if _, ok := body["destIP"]; ok {
				t.Fatal("不该附加 destIP")
			}
		} else if body["destIP"] != tc.ip {
			t.Fatal("下发 IP 丢失")
		}
		wireBody := request[7 : 7+n]
		index := bytes.LastIndex(wireBody, []byte(`,"xRequestSig":`))
		if index < 0 {
			t.Fatal("签名缺失")
		}
		unsigned := append(append([]byte(nil), wireBody[:index]...), '}')
		mac := hmac.New(sha256.New, []byte("fixed-test-key"))
		_, _ = mac.Write(unsigned)
		if body["xRequestSig"] != strings.ToUpper(hex.EncodeToString(mac.Sum(nil))) {
			t.Fatal("签名覆盖范围错误")
		}
	}
}

func TestTCPDialCancellationClosesAndJoins(t *testing.T) {
	srv := newFake(t, ztnatest.Options{})
	client := newTestClient(t, srv, testPass)
	sess, err := client.Connect(t.Context(), ConnectOptions{})
	closeSessionAfterTest(t, sess)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	var active atomic.Int32
	client.opts.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		active.Add(1)
		defer active.Add(-1)
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	target, _ := NewTCPTarget("10.1.2.3", 443)
	done := make(chan error, 1)
	go func() { _, err := sess.DialTCP(t.Context(), target); done <- err }()
	awaitSignal(t, entered)
	if err := sess.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil || active.Load() != 0 {
		t.Fatal("关闭未等待拨号", err, active.Load())
	}
	if _, err := sess.Resources(); !errors.Is(err, ErrResourcesUnavailable) {
		t.Fatal("关闭后仍发布表")
	}
}

func TestTCPDialCandidateOrderAndAuthRejection(t *testing.T) {
	for _, authRejected := range []bool{false, true} {
		t.Run(fmt.Sprint(authRejected), func(t *testing.T) {
			opts := ztnatest.Options{L4ConnectStatus: 5, Apps: []ztnatest.App{{ID: "app", AccessModel: "L3VPN", Host: "db.example.edu", Protocol: "tcp", Port: "443", IP: []string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"}}}}
			if authRejected {
				opts.L4AuthCode = 12345
			}
			srv := newFake(t, opts)
			client := newTestClient(t, srv, testPass)
			sess, err := client.Connect(t.Context(), ConnectOptions{})
			closeSessionAfterTest(t, sess)
			if err != nil {
				t.Fatal(err)
			}
			target, _ := NewTCPTarget("db.example.edu", 443)
			_, err = sess.DialTCP(t.Context(), target)
			want := 4
			var rejected *TCPConnectError
			if authRejected {
				want = 1
				if !errors.Is(err, ErrTCPAuthRejected) {
					t.Fatal("鉴权错误类别丢失", err)
				}
			} else if !errors.As(err, &rejected) || rejected.Reply != 5 {
				t.Fatal("目标错误类别丢失", err)
			}
			requests := srv.TCPRequests()
			if len(requests) != want {
				t.Fatal("遗漏候选或鉴权停止条件失效", len(requests))
			}
			for i, request := range requests {
				if request.AppID != "app" || request.DestAddr != "db.example.edu:443" || request.DestIP != fmt.Sprintf("198.51.100.%d", i+1) || request.Host != request.DestIP {
					t.Fatal("候选顺序或授权身份改变", i)
				}
			}
			if sess.Err() != nil || srv.Tunnels() != 0 {
				t.Fatal("局部建连错误终止会话或启动 L3")
			}
		})
	}
}

func TestTCPDialAttemptBudgetIncludesAllNodes(t *testing.T) {
	nodes := make([]string, 65)
	for i := range nodes {
		nodes[i] = fmt.Sprintf("node-%02d.example.test:441", i)
	}
	srv := newFake(t, ztnatest.Options{Nodes: nodes, L4ConnectStatus: 5})
	client := newTestClient(t, srv, testPass)
	sess, err := client.Connect(t.Context(), ConnectOptions{})
	closeSessionAfterTest(t, sess)
	if err != nil {
		t.Fatal(err)
	}
	// 65 个逻辑节点指向同一受控 TLS 实例，不查询测试域名的 DNS。
	client.opts.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Addr())
	}
	target, _ := NewTCPTarget("10.1.2.3", 443)
	_, err = sess.DialTCP(t.Context(), target)
	var rejected *TCPConnectError
	if !errors.As(err, &rejected) || rejected.Reply != 5 || len(srv.TCPRequests()) != 64 {
		t.Fatal("总尝试预算按节点重置或未执行完整预算", err, len(srv.TCPRequests()))
	}
}
