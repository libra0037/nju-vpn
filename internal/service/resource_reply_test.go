package service

import (
	"bufio"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/ipc"
	"github.com/libra0037/nju-vpn/internal/ztna"
	"github.com/libra0037/nju-vpn/internal/ztnatest"
)

func TestLargeResourcesReplyIsCompleteAndReadOnly(t *testing.T) {
	for _, tc := range []struct {
		name  string
		count int
		host  string
	}{
		{"60KiB-input", 512, "192.0.2.1"},
		{"large-domains", 128, strings.Repeat("x", 1024)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			apps := make([]ztnatest.App, tc.count)
			for i := range apps {
				apps[i] = ztnatest.App{ID: "app", NodeGroupID: "g", AccessModel: "L3VPN", Host: tc.host, Protocol: "tcp", Port: "443"}
			}
			srv := newFakeServer(t, ztnatest.Options{Apps: apps})
			svc := newTestService(t, srv, newTestConfig(t, srv))
			if err := svc.Start(false, ""); err != nil {
				t.Fatal(err)
			}
			calls, tunnels, sms, logouts := srv.ResourceCalls(), srv.Tunnels(), srv.SMSSends(), srv.LogoutCount()
			server := NewServer(svc, nil)
			client, conn := net.Pipe()
			done := make(chan struct{})
			go func() { defer close(done); server.handle(conn) }()
			t.Cleanup(func() { client.Close(); <-done })
			if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(client)
			// 同一连接连续查询，覆盖编码、发送及完成后释放名额。
			for range 2 {
				if err := ipc.WriteRequest(client, ipc.Request{Command: ipc.CmdResources}); err != nil {
					t.Fatal(err)
				}
				resp, err := ipc.ReadResourcesResponse(reader)
				if err != nil || resp.Code != ipc.CodeOK || len(resp.Message) <= ipc.MaxLineBytes {
					t.Fatal("大资源响应被拒绝或截断", err, resp.Code, len(resp.Message))
				}
				var list []ztna.Resource
				if err := json.Unmarshal([]byte(resp.Message), &list); err != nil || len(list) != tc.count {
					t.Fatal("资源行丢失", err, len(list))
				}
				for _, app := range list {
					if app.ID != "app" || len(app.AddressList) != 1 || app.AddressList[0].Host != tc.host {
						t.Fatal("资源字段丢失")
					}
				}
			}
			if calls != srv.ResourceCalls() || tunnels != srv.Tunnels() || sms != srv.SMSSends() || logouts != srv.LogoutCount() || svc.Status().State != StateUp {
				t.Fatal("资源查询改变了会话或触发外部操作")
			}
		})
	}
}

type resourcesWriteSignalConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *resourcesWriteSignalConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Write(p)
}

func TestResourceReplyBudgetCoversBlockedWriteAndReleasesOnError(t *testing.T) {
	server := NewServer(&Service{status: newStatusStore(Identity{})}, nil)
	client, conn := net.Pipe()
	blocked := &resourcesWriteSignalConn{Conn: conn, started: make(chan struct{})}
	firstErr := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		firstErr <- server.reply(blocked, ipc.Request{Command: ipc.CmdResources})
	}()
	t.Cleanup(func() {
		client.Close()
		conn.Close()
		<-done
	})
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("响应未进入写入阶段")
	}
	request := func(req ipc.Request) ipc.Response {
		t.Helper()
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		errs := make(chan error, 1)
		go func() { errs <- server.reply(b, req) }()
		a.SetDeadline(time.Now().Add(time.Second))
		resp, err := ipc.ReadResourcesResponse(bufio.NewReader(a))
		if err != nil {
			t.Fatal(err)
		}
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
		return resp
	}
	if resp := request(ipc.Request{Command: ipc.CmdResources}); resp.Code != ipc.CodeRejected || !strings.Contains(resp.Message, "正在进行") {
		t.Fatal("写入阻塞期间仍接受第二次编码", resp)
	}
	if resp := request(ipc.Request{Command: ipc.CmdState}); resp.Code != ipc.CodeOK || resp.Message != "idle" {
		t.Fatal("资源响应阻塞了普通查询", resp)
	}
	if resp := request(ipc.Request{Command: ipc.CmdResources, Args: []string{"unexpected"}}); resp.Code != ipc.CodeBadRequest {
		t.Fatal("排队预算覆盖了参数拒绝", resp)
	}
	client.Close()
	if err := <-firstErr; err == nil {
		t.Fatal("断开的写入仍成功")
	}
	<-done
	if resp := request(ipc.Request{Command: ipc.CmdResources}); resp.Code != ipc.CodeRejected || resp.Message != ztna.ErrResourcesUnavailable.Error() {
		t.Fatal("写入失败后未释放名额", resp)
	}
}
