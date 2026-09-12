package service

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/vpn"
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
