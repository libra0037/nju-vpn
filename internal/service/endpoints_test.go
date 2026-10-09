package service

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/config"
	"github.com/libra0037/nju-vpn/internal/ipc"
	"github.com/libra0037/nju-vpn/internal/ztna"
	"github.com/libra0037/nju-vpn/internal/ztnatest"
)

func socksConfig() config.SOCKS5 {
	return config.SOCKS5{Enabled: true, ListenHost: "loopback", MaxConnections: 8, MaxDials: 2}
}

func openSOCKS(t *testing.T, svc *Service, target []byte, allowClose ...bool) (*net.TCPConn, *bufio.Reader, byte) {
	t.Helper()
	port := svc.Status().SOCKS5.Port
	conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c := conn.(*net.TCPConn)
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	// 固定字节把方法、目标和业务预读放在一次 Write 中。
	if _, err := c.Write(append([]byte{5, 1, 0}, target...)); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(c)
	var method [2]byte
	if _, err := io.ReadFull(r, method[:]); err != nil || method != [2]byte{5, 0} {
		t.Fatal("方法协商错误", method, err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(r, reply[:]); err != nil {
		if len(allowClose) == 1 && allowClose[0] {
			return c, r, 255
		}
		t.Fatal("目标回复被截断", err)
	}
	if reply[1] == 0 && !bytes.Equal(reply[:], []byte{5, 0, 0, 1, 198, 51, 100, 9, 0x9c, 0x40}) {
		t.Fatal("绑定地址不是校园 CONNECT 回复", reply)
	}
	return c, r, reply[1]
}

func TestEndpointEnableCombinationsAndQueries(t *testing.T) {
	for _, tc := range []struct{ wg, socks bool }{{false, false}, {true, false}, {false, true}, {true, true}} {
		t.Run(fmt.Sprintf("wg=%v/socks=%v", tc.wg, tc.socks), func(t *testing.T) {
			srv := newFakeServer(t, ztnatest.Options{})
			cfg := newTestConfig(t, srv)
			cfg.WireGuard.Enabled = tc.wg
			if !tc.wg {
				cfg.WireGuard = config.WireGuard{}
			}
			if tc.socks {
				cfg.SOCKS5 = socksConfig()
			}
			svc := newTestService(t, srv, cfg)
			err := svc.Start(false, "")
			if !tc.wg && !tc.socks {
				if !errors.Is(err, ErrBadState) || srv.ResourceCalls() != 0 || srv.Tunnels() != 0 {
					t.Fatal("关闭全部端点仍登录", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			st := svc.Status()
			if !st.Ready || !st.SessionReady || st.WireGuard.Enabled != tc.wg || st.SOCKS5.Enabled != tc.socks || (st.Tunnel != nil) != tc.wg {
				t.Fatal("就绪不对应实际启用端点", st)
			}
			wantTunnels := 0
			if tc.wg {
				wantTunnels = 1
			}
			if srv.Tunnels() != wantTunnels || (svc.brSnapshot.Load() != nil) != tc.wg {
				t.Fatal("创建了无关 L3 或 UDP 承载")
			}
			server := NewServer(svc, nil)
			resp := server.dispatch(ipc.Request{Command: ipc.CmdResources})
			if resp.Code != 200 {
				t.Fatal("无 L3 时无法查询资源", resp.Code)
			}
			if tc.socks {
				c, r, reply := openSOCKS(t, svc, []byte{5, 1, 0, 1, 10, 1, 2, 3, 1, 187, 'h', 'i'})
				if reply != 0 {
					t.Fatal("CONNECT 失败", reply)
				}
				var echo [2]byte
				if _, err := io.ReadFull(r, echo[:]); err != nil || string(echo[:]) != "hi" {
					t.Fatal("字节转发失败", err)
				}
				c.Close()
			}
			if err := svc.Stop(); err != nil {
				t.Fatal(err)
			}
			if svc.Status().Ready || srv.LogoutCount() != 1 {
				t.Fatal("全局停止未撤销就绪或重复登出")
			}
		})
	}
}

func TestStoppingAndRestartingEndpointsPreservesOtherDataPath(t *testing.T) {
	srv := newFakeServer(t, ztnatest.Options{})
	cfg := newTestConfig(t, srv)
	cfg.SOCKS5 = socksConfig()
	svc := newTestService(t, srv, cfg)
	if err := svc.Start(false, ""); err != nil {
		t.Fatal(err)
	}
	c, r, reply := openSOCKS(t, svc, []byte{5, 1, 0, 1, 10, 1, 2, 3, 1, 187})
	if reply != 0 {
		t.Fatal(reply)
	}
	if err := svc.StopEndpoint("wireguard"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("still-alive")); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 11)
	if _, err := io.ReadFull(r, body); err != nil || string(body) != "still-alive" {
		t.Fatal("停止 L3 影响 L4", err)
	}
	if !svc.Status().Ready || svc.Status().WireGuard.Listening || srv.LogoutCount() != 0 {
		t.Fatal("局部停止登出了共享会话")
	}
	if err := svc.StartEndpoint("wireguard"); err != nil {
		t.Fatal(err)
	}
	if err := svc.StopEndpoint("socks5"); err != nil {
		t.Fatal(err)
	}
	if st := svc.Status(); !st.Ready || st.Tunnel == nil || !st.Tunnel.Connected || st.SOCKS5.Listening {
		t.Fatal("停止 SOCKS 影响 L3", st)
	}
	if err := svc.StartEndpoint("socks5"); err != nil {
		t.Fatal(err)
	}
	if srv.ResourceCalls() != 1 || srv.LogoutCount() != 0 {
		t.Fatal("局部启停重新登录或取资源")
	}
	if err := svc.Stop(); err != nil {
		t.Fatal(err)
	}
	if srv.LogoutCount() != 1 {
		t.Fatal("登出次数错误")
	}
}

func TestOrdinaryL3FailuresKeepSOCKSFlows(t *testing.T) {
	for _, startup := range []bool{true, false} {
		t.Run(fmt.Sprint(startup), func(t *testing.T) {
			opts := ztnatest.Options{RejectL3Reconnect: !startup}
			if startup {
				opts.L3HandshakeCode = 12345
			}
			srv := newFakeServer(t, opts)
			cfg := newTestConfig(t, srv)
			cfg.SOCKS5 = socksConfig()
			svc := newTestService(t, srv, cfg)
			if err := svc.Start(false, ""); err != nil {
				t.Fatal("L3 局部失败终止健康 SOCKS", err)
			}
			c, r, reply := openSOCKS(t, svc, []byte{5, 1, 0, 1, 10, 1, 2, 3, 1, 187})
			if reply != 0 {
				t.Fatal(reply)
			}
			if !startup {
				srv.CloseTunnel()
				waitStatus(t, svc, func(st Status) bool { return st.State == StateUp && st.WireGuard.Failure != "" && !st.Retrying })
			}
			if _, err := c.Write([]byte("alive")); err != nil {
				t.Fatal(err)
			}
			var body [5]byte
			if _, err := io.ReadFull(r, body[:]); err != nil || string(body[:]) != "alive" {
				t.Fatal("L3 故障关闭了 L4 流", err)
			}
			st := svc.Status()
			if st.Ready || !st.SessionReady || !st.SOCKS5.Listening || srv.LogoutCount() != 0 {
				t.Fatal("局部故障没有独立报告", st)
			}
		})
	}
}

func TestSOCKSBindFailureDoesNotPreventWireGuard(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv := newFakeServer(t, ztnatest.Options{})
	cfg := newTestConfig(t, srv)
	cfg.SOCKS5 = socksConfig()
	cfg.SOCKS5.ListenPort = ln.Addr().(*net.TCPAddr).Port
	svc := newTestService(t, srv, cfg)
	if err := svc.Start(false, ""); err != nil {
		t.Fatal("SOCKS 端口占用带走 L3", err)
	}
	st := svc.Status()
	if st.Ready || !st.SessionReady || st.Tunnel == nil || !st.Tunnel.Connected || st.SOCKS5.Failure != "network" {
		t.Fatal("端口故障没有独立显示", st)
	}
}

func TestSOCKSRelayLargeResponseAfterClientHalfClose(t *testing.T) {
	payload := bytes.Repeat([]byte{0, 1, 2, 255}, 256*1024)
	srv := newFakeServer(t, ztnatest.Options{TCPGreeting: []byte("early"), TCPHandler: func(c net.Conn) {
		body, err := io.ReadAll(c)
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("response:"))
		_, _ = c.Write(body)
		_ = c.(interface{ CloseWrite() error }).CloseWrite()
	}})
	cfg := newTestConfig(t, srv)
	cfg.WireGuard = config.WireGuard{}
	cfg.SOCKS5 = socksConfig()
	svc := newTestService(t, srv, cfg)
	if err := svc.Start(false, ""); err != nil {
		t.Fatal(err)
	}
	c, r, reply := openSOCKS(t, svc, []byte{5, 1, 0, 1, 10, 1, 2, 3, 1, 187})
	if reply != 0 {
		t.Fatal(reply)
	}
	var early [5]byte
	if _, err := io.ReadFull(r, early[:]); err != nil || string(early[:]) != "early" {
		t.Fatal("服务端先发数据丢失", err)
	}
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(body, append([]byte("response:"), payload...)) {
		t.Fatal("半关闭或大流量转发失败", len(body), err)
	}
}

func TestSIDExpiryFromEitherPathClosesBothEndpoints(t *testing.T) {
	for _, fromL3 := range []bool{false, true} {
		t.Run(fmt.Sprint(fromL3), func(t *testing.T) {
			opts := ztnatest.Options{}
			if fromL3 {
				opts.L3AuthCode = 75500002
			} else {
				opts.L4AuthCode = 75500002
			}
			srv := newFakeServer(t, opts)
			cfg := newTestConfig(t, srv)
			cfg.SOCKS5 = socksConfig()
			svc := newTestService(t, srv, cfg)
			if err := svc.Start(false, ""); err != nil {
				t.Fatal(err)
			}
			if fromL3 {
				// 独立固定的 IPv4/TCP 目的包触发校园逐流鉴权。
				packet := []byte{0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 172, 16, 0, 9, 10, 1, 2, 3, 0x9c, 0x40, 1, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0, 0, 0, 0, 0, 0, 0}
				if err := svc.sessionSnapshot.Load().Endpoint().Send(packet); err != nil {
					t.Fatal(err)
				}
			} else {
				_, _, reply := openSOCKS(t, svc, []byte{5, 1, 0, 1, 10, 1, 2, 3, 1, 187}, true)
				if reply == 0 {
					t.Fatal("SID 失效回复成功")
				}
			}
			waitStatus(t, svc, func(st Status) bool { return st.State == StateError })
			st := svc.Status()
			if st.Ready || st.SessionReady || st.SOCKS5.Listening || st.Failure != "session_expired" || srv.LogoutCount() != 1 || srv.Tunnels() != 1 {
				t.Fatal("共享失效未收敛或重新使用 SID", st, srv.LogoutCount(), srv.Tunnels())
			}
		})
	}
}

func TestL4TargetFailureKeepsSharedSessionAndL3(t *testing.T) {
	srv := newFakeServer(t, ztnatest.Options{L4ConnectStatus: 5})
	cfg := newTestConfig(t, srv)
	cfg.SOCKS5 = socksConfig()
	svc := newTestService(t, srv, cfg)
	if err := svc.Start(false, ""); err != nil {
		t.Fatal(err)
	}
	_, _, reply := openSOCKS(t, svc, []byte{5, 1, 0, 1, 10, 1, 2, 3, 1, 187})
	if reply != 5 {
		t.Fatal("目标拒绝被误报成功", reply)
	}
	if !svc.Status().Ready || srv.LogoutCount() != 0 || srv.Tunnels() != 1 {
		t.Fatal("普通 L4 失败影响 WireGuard")
	}
	_, err := svc.ResourcesJSON(10)
	if !errors.Is(err, ipc.ErrResourceSnapshotTooLarge) {
		t.Fatal(err)
	}
}

func TestTrustSessionExpiryPreventsStartingDataEndpoints(t *testing.T) {
	srv := newFakeServer(t, ztnatest.Options{QueryDeviceCode: 75500002})
	cfg := newTestConfig(t, srv)
	cfg.SOCKS5 = socksConfig()
	svc := newTestService(t, srv, cfg)
	err := svc.Start(true, "")
	var gone *ztna.ErrSessionGone
	if !errors.As(err, &gone) {
		t.Fatal("共享失效被当成可忽略授信错误", err)
	}
	st := svc.Status()
	if st.Ready || st.SessionReady || st.SOCKS5.Listening || st.Failure != "session_expired" || srv.Tunnels() != 0 || srv.LogoutCount() != 1 {
		t.Fatal("使用失效 SID 启动端点或重复登出", st)
	}
}

func TestEndpointCommandsValidateBeforeSideEffects(t *testing.T) {
	srv := newFakeServer(t, ztnatest.Options{})
	cfg := newTestConfig(t, srv)
	svc := newTestService(t, srv, cfg)
	server := NewServer(svc, nil)
	for _, cmd := range []string{ipc.CmdEndpointStart, ipc.CmdEndpointStop} {
		for _, args := range [][]string{nil, {"invalid"}, {"wireguard", "socks5"}} {
			if r := server.dispatch(ipc.Request{Command: cmd, Args: args}); r.Code != 400 {
				t.Fatal("非法端点请求被执行", r)
			}
		}
	}
	if srv.ResourceCalls() != 0 || srv.LogoutCount() != 0 {
		t.Fatal("校验做了网络操作")
	}
	if err := svc.StartEndpoint("socks5"); !errors.Is(err, ErrNotRunning) {
		t.Fatal("未登录创建端点", err)
	}
}

func waitStatus(t *testing.T, svc *Service, ready func(Status) bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ready(svc.Status()) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("状态未收敛", svc.Status())
}
