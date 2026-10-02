package ztna

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/l3"
	"github.com/libra0037/nju-vpn/internal/ztnatest"
)

type deadlineGate struct {
	net.Conn
	entered, release chan struct{}
	once             sync.Once
	clearOnly        bool
}

func (c *deadlineGate) SetDeadline(d time.Time) error {
	if !c.clearOnly || d.IsZero() {
		c.once.Do(func() { close(c.entered); <-c.release })
	}
	if c.Conn != nil {
		return c.Conn.SetDeadline(d)
	}
	return nil
}
func awaitSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("未到达交错屏障")
	}
}
func TestCancelWatcherJoinsBeforeDeadlineCanBeCleared(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	c := &deadlineGate{entered: make(chan struct{}), release: make(chan struct{})}
	stop := watchCancel(ctx, c)
	cancel()
	awaitSignal(t, c.entered)
	done := make(chan struct{})
	go func() { stop(); close(done) }()
	select {
	case <-done:
		close(c.release)
		t.Fatal("取消监听未等待设置期限完成")
	case <-time.After(30 * time.Millisecond):
	}
	close(c.release)
	awaitSignal(t, done)
	stop()
}
func TestCloseRejectsReconnectCompletedDuringShutdown(t *testing.T) {
	srv := newFake(t, ztnatest.Options{})
	client := newTestClient(t, srv, testPass)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseGate := func() { releaseOnce.Do(func() { close(release) }) }
	var armed atomic.Bool
	client.opts.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		c, err := srv.Dial(ctx, network, address)
		if err == nil && armed.Load() {
			return &deadlineGate{Conn: c, entered: entered, release: release, clearOnly: true}, nil
		}
		return c, err
	}
	sess, err := client.Connect(t.Context(), ConnectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { releaseGate(); sess.Close(context.Background()) })
	var restored atomic.Int32
	runDone := make(chan struct{})
	go func() { defer close(runDone); sess.Run(t.Context(), LinkEvents{Restored: func() { restored.Add(1) }}) }()
	armed.Store(true)
	srv.CloseTunnel()
	awaitSignal(t, entered)
	closeDone := make(chan struct{})
	go func() { sess.Close(context.Background()); close(closeDone) }()
	// 先证明 Close 已设置关闭事实；随后交出已经握手成功的迟到连接。
	deadline := time.After(3 * time.Second)
	for {
		sess.mu.Lock()
		closed := sess.closed
		sess.mu.Unlock()
		if closed {
			break
		}
		select {
		case <-deadline:
			releaseGate()
			t.Fatal("Close 未取得会话所有权")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	releaseGate()
	awaitSignal(t, closeDone)
	awaitSignal(t, runDone)
	sess.mu.Lock()
	active := sess.active
	sess.mu.Unlock()
	if active != nil || restored.Load() != 0 {
		t.Fatal("关闭后仍发布重连或恢复事件")
	}
	if !errors.Is(sess.Endpoint().Send([]byte{1}), l3.ErrNoUplink) {
		t.Fatal("关闭后仍留上行回调")
	}
	if srv.LogoutCount() != 1 {
		t.Fatal("未尝试独立登出")
	}
}

type blockedWriteConn struct {
	net.Conn
	entered, closed chan struct{}
	once            sync.Once
	closeOnce       sync.Once
}

func (c *blockedWriteConn) Write([]byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	<-c.closed
	return 0, net.ErrClosed
}
func (c *blockedWriteConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}
func TestTunnelCloseInterruptsBlockedRawWriteAndJoinsWorkers(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	raw := &blockedWriteConn{Conn: a, entered: make(chan struct{}), closed: make(chan struct{})}
	tc := &tunnelConn{conn: raw, raw: raw, flows: newFlowTable(), ep: l3.New(), closeCh: make(chan struct{}), logf: func(string, ...any) {}}
	tc.unregister = tc.ep.SetUplink(func(p []byte) error { return tc.write(p) })
	tc.workers.Go(func() { _ = tc.ep.Send([]byte{1}) })
	awaitSignal(t, raw.entered)
	done := make(chan struct{})
	go func() { tc.Close(); close(done) }()
	awaitSignal(t, done)
	if !errors.Is(tc.ep.Send(nil), l3.ErrNoUplink) {
		t.Fatal("关闭没有撤销自身绑定")
	}
	tc.Close()
}
