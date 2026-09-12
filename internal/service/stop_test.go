package service

import (
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/vpn"
	"github.com/libra0037/nju-vpn/internal/vpntest"
)

// TestStopInterruptsRunningStart 验证 stop 不会排在一条卡住的 start 后面。
//
// 命令在 actor 里串行，而一次登录最坏要走三分多钟（短信、退避重试）；
// stop 的语义却是"现在就断"。这里把 harness 注入的假 HTTP 与假隧道全部
// 关掉，让 start 卡在真实拨号路径上，再验证 stop 能立刻打断它。
func TestStopInterruptsRunningStart(t *testing.T) {
	h := newHarness(t)

	// 覆盖 harness 的注入：所有出站连接（含 portal 的 HTTP）都走
	// 下面这个永不返回的 dialer。
	h.svc.SetClientOptions(func(opts *vpn.Options) {
		opts.HTTP = nil
		opts.PortalTLS = nil
		opts.TunnelTLS = nil
		opts.Timeouts = vpn.Timeouts{HTTP: 30 * time.Second, Handshake: 30 * time.Second}
	})

	dialing := make(chan struct{})
	block := make(chan struct{})
	var once sync.Once
	h.svc.SetDialer(func(network, addr string) (net.Conn, error) {
		once.Do(func() { close(dialing) })
		<-block
		return nil, errors.New("不会走到这里")
	})

	done := make(chan error, 1)
	go func() { done <- h.svc.StartWithPassword("p") }()

	select {
	case <-dialing:
	case <-time.After(5 * time.Second):
		t.Fatal("start 没有走到拨号这一步")
	}

	start := time.Now()
	if err := h.svc.Stop(); err != nil {
		t.Fatalf("stop 应当成功，实际 %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("stop 被卡住的 start 拖了 %s", elapsed)
	}
	waitState(t, h.svc, StateIdle, 3*time.Second)

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("被打断的 start 应当返回错误")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("被打断的 start 没有返回")
	}
}

// 回归：排队中的 start 会被"已经请求断开"挡掉。
//
// 命令在 actor 里串行。如果 start 排在队列里、用户在它执行之前敲了 stop，
// 旧实现会让它照常跑完（重新登录、发短信、建隧道），用户看到的是
// "stop 报超时，可隧道后来又自己起来了"。
func TestQueuedStartIsDroppedAfterStopRequested(t *testing.T) {
	h := newHarness(t)
	h.svc.stopPending.Store(true)

	if err := h.svc.StartWithPassword("p"); !errors.Is(err, ErrStopRequested) {
		t.Fatalf("应当以 ErrStopRequested 收场，实际 %v", err)
	}
	// "没执行"的含义就是一次登录都没发生。
	if n := h.portal.Count("/por/login_psw.csp"); n != 0 {
		t.Fatalf("被丢弃的 start 不该发起登录，实际请求 %d 次", n)
	}
	if state := h.svc.Status().State; state != StateIdle {
		t.Fatalf("状态不该被改动，实际 %s", state)
	}
}

// stop 执行完之后标记要清掉：下一条 start 是新意图，不能被它挡住。
func TestStopClearsStopRequestedFlag(t *testing.T) {
	h := newHarness(t)
	if err := h.svc.StartWithPassword("p"); err != nil {
		t.Fatalf("第一次 start 失败: %v", err)
	}
	waitState(t, h.svc, StateUp, 3*time.Second)

	if err := h.svc.Stop(); err != nil {
		t.Fatalf("stop 失败: %v", err)
	}
	waitState(t, h.svc, StateIdle, 3*time.Second)
	if h.svc.stopPending.Load() {
		t.Fatal("stop 执行完后标记应当已经清掉")
	}

	// 紧接着的 start 必须能真的建起来。
	// 假 portal 是"一条响应消耗一次"的队列，第二次登录要再放一份剧本。
	h.portal.On("/por/login_auth.csp", vpntest.Response{Body: vpntest.LoginAuthPage()})
	h.portal.On("/por/login_psw.csp", vpntest.Response{
		Body: "<Auth><Result>1</Result><NextAuth>-1</NextAuth><TwfID>fedcba9876543210</TwfID></Auth>",
	})
	if err := h.svc.StartWithPassword("p"); err != nil {
		t.Fatalf("stop 之后的 start 应当正常: %v", err)
	}
	waitState(t, h.svc, StateUp, 3*time.Second)
}

// 回归：登出没成功要让用户看见。
//
// 服务端同一账号只允许一条会话，登出失败意味着名额还占着、下一次 start
// 可能被拒。旧实现只写一行日志，stop 照样回"隧道已断开"。
func TestStopReportsLogoutFailure(t *testing.T) {
	h := newHarness(t)
	if err := h.svc.StartWithPassword("p"); err != nil {
		t.Fatalf("start 失败: %v", err)
	}
	waitState(t, h.svc, StateUp, 3*time.Second)

	h.portal.Set("/por/logout.csp", vpntest.Response{Status: 500, Body: "boom"})

	if err := h.svc.Stop(); err != nil {
		t.Fatalf("本地断开应当成功，实际 %v", err)
	}
	waitState(t, h.svc, StateIdle, 3*time.Second)
	if detail := h.svc.Status().Detail; !strings.Contains(detail, "登出未成功") {
		t.Fatalf("状态说明里应提到登出失败，实际 %q", detail)
	}
}
