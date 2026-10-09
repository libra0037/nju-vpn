package service

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/libra0037/nju-vpn/internal/ipc"
	"github.com/libra0037/nju-vpn/internal/wireguard"
	"github.com/libra0037/nju-vpn/internal/ztna"
	"github.com/libra0037/nju-vpn/internal/ztnatest"
)

func TestStatusDiagnosticsAreReadOnlyAndSeparateReadiness(t *testing.T) {
	srv := newFakeServer(t, ztnatest.Options{})
	cfg := newTestConfig(t, srv)
	key, _ := wireguard.GenerateKey()
	pub, _ := key.PublicKey()
	cfg.WireGuard.PeerPublicKey = pub.String()
	svc := newTestService(t, srv, cfg)
	if err := svc.Start(false, ""); err != nil {
		t.Fatal(err)
	}
	packet, err := hex.DecodeString("4500001c00010000401100000a424202c63364013039003500080000")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.sessionSnapshot.Load().Endpoint().Send(packet); !errors.Is(err, ztna.ErrResourceUnmatched) {
		t.Fatal("独立样例未触发资源拒绝", err)
	}
	st := svc.Status()
	if st.State != StateUp || !st.WireGuard.Configured || st.WireGuard.Ready || st.Tunnel == nil || !st.Tunnel.Connected || st.Tunnel.Rejected.ResourceUnmatched != 1 {
		t.Fatalf("校园 up 与 WireGuard 握手未区分: %+v", st)
	}
	before := []int{srv.ResourceCalls(), srv.Tunnels(), srv.SMSSends(), srv.LogoutCount()}
	server := NewServer(svc, nil)
	for _, args := range [][]string{nil, {"json"}} {
		resp := server.dispatch(ipc.Request{Command: ipc.CmdStatus, Args: args})
		if len(args) == 0 {
			if resp.Code != ipc.CodeOK {
				t.Fatal("默认状态查询没有按校园链路返回成功")
			}
			continue
		}
		var snapshot Status
		if resp.Code != ipc.CodeOK || json.Unmarshal([]byte(resp.Message), &snapshot) != nil {
			t.Fatal("JSON 诊断响应失败", resp.Code)
		}
		if snapshot.Tunnel.Rejected.ResourceUnmatched != 1 || snapshot.WireGuard.Ready {
			t.Fatal("诊断判据丢失")
		}
		snapshot.Tunnel.Rejected.ResourceUnmatched = 99
	}
	if after := []int{srv.ResourceCalls(), srv.Tunnels(), srv.SMSSends(), srv.LogoutCount()}; fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatal("状态查询引起网络副作用")
	}
	if svc.Status().Tunnel.Rejected.ResourceUnmatched != 1 {
		t.Fatal("快照修改了内部状态")
	}
	for _, args := range [][]string{{"bogus"}, {"json", "json"}, {"check"}, {"json", "check"}} {
		if resp := server.dispatch(ipc.Request{Command: ipc.CmdStatus, Args: args}); resp.Code != ipc.CodeBadRequest {
			t.Fatal("非法状态参数未拒绝")
		}
	}
	if err := svc.Stop(); err != nil {
		t.Fatal(err)
	}
	resp := server.dispatch(ipc.Request{Command: ipc.CmdStatus, Args: []string{"json"}})
	var stopped Status
	if resp.Code != ipc.CodeRejected || json.Unmarshal([]byte(resp.Message), &stopped) != nil || stopped.WireGuard.Ready || stopped.Tunnel != nil {
		t.Fatal("停止后的 JSON 巡检状态错误")
	}
}

func TestStatusReadinessDoesNotDependOnOutputFormat(t *testing.T) {
	for _, tc := range []struct {
		state    State
		retrying bool
		wantCode int
	}{
		{StateIdle, false, 409},
		{StateLoggingIn, false, 409},
		{StateAuthPending, false, 409},
		{StateError, false, 409},
		{StateUp, false, 200},
		{StateUp, false, 409},
		{StateUp, true, 409},
	} {
		t.Run(fmt.Sprintf("%s/retrying=%t", tc.state, tc.retrying), func(t *testing.T) {
			srv := newFakeServer(t, ztnatest.Options{})
			svc := newTestService(t, srv, newTestConfig(t, srv))
			if tc.state == StateUp && (tc.wantCode == 200 || tc.retrying) {
				if err := svc.Start(false, ""); err != nil {
					t.Fatal(err)
				}
			} else {
				// 无实际会话的 up 必须拒绝，防止只用状态标签判断就绪。
				if tc.state == StateAuthPending || tc.state == StateUp {
					svc.status.set(StateLoggingIn, "")
				}
				svc.status.set(tc.state, "")
			}

			if tc.retrying {
				svc.status.setRetrying(true)
			}
			server := NewServer(svc, nil)
			for _, args := range [][]string{nil, {"json"}} {
				resp := server.dispatch(ipc.Request{Command: ipc.CmdStatus, Args: args})
				if resp.Code != tc.wantCode {
					t.Fatal("输出格式改变了就绪判据", args, resp.Code)
				}
				if len(args) != 0 {
					var snapshot Status
					if json.Unmarshal([]byte(resp.Message), &snapshot) != nil || snapshot.State != tc.state || snapshot.Retrying != tc.retrying {
						t.Fatal("非零结果未保留完整状态快照")
					}
				}
			}
		})
	}
}

func TestFailureCategories(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{ztna.ErrControlTLS, "control_tls"}, {ztna.ErrNodeUntrusted, "node_untrusted"}, {ztna.ErrNodeTLS, "node_tls"},
		{&ztna.ErrCodeRejected{Code: 123}, "auth_rejected"}, {&ztna.ErrSessionGone{Code: 75500002}, "session_expired"},
		{context.DeadlineExceeded, "timeout"}, {context.Canceled, "canceled"}, {&ztna.ProtocolError{What: "private detail"}, "protocol"},
	} {
		store := newStatusStore(Identity{})
		store.setError("failed", fmt.Errorf("wrapped: %w", tc.err))
		if store.Get().Failure != tc.want {
			t.Fatal("类别依赖错误文本", tc.want, store.Get().Failure)
		}
		store.set(StateLoggingIn, "login")
		store.set(StateUp, "up")
		store.setLinkFailure("reconnecting", tc.err)
		if st := store.Get(); !st.Retrying || st.Failure != tc.want {
			t.Fatal("重连缺少原因类别")
		}
		store.setRetrying(false)
		if store.Get().Failure != "" {
			t.Fatal("恢复后残留旧失败原因")
		}
	}
}
