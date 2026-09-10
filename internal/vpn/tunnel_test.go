package vpn

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// 建立一条可以跑隧道的连接，供流相关的用例复用。
func connectedSession(t *testing.T, s *script) *Session {
	t.Helper()
	client := newTestClient(t, s)
	sess, err := client.Connect(context.Background(), ConnectOptions{Username: "u", Password: "p"})
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	t.Cleanup(func() { sess.Close(context.Background()) })
	return sess
}

// 隧道必须双向搬运数据：上行包进隧道，下行包交给承载侧。
func TestSessionRunMovesPacketsBothWays(t *testing.T) {
	s := newScript(t)
	sess := connectedSession(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- sess.Run(ctx) }()

	// 上行：承载侧写包，隧道服务端应该收到。
	uplink := []byte{0x45, 0x00, 0x00, 0x1c, 0, 0, 0, 0, 64, 17, 0, 0, 10, 66, 66, 2, 172, 29, 56, 18}
	if err := waitUplinkReady(sess.Endpoint(), 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := sess.Endpoint().Send(uplink); err != nil {
		t.Fatalf("上行发送失败: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		if len(s.tunnel.Stats().Uplink) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("隧道服务端没有收到上行数据")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// 下行：假装隧道里数据已经就绪，然后第一次 Read 会触发投递。
	if err := s.tunnel.WaitRecvStream(2 * time.Second); err != nil {
		t.Fatal(err)
	}
	downlink := []byte{0x45, 0x00, 0x00, 0x1c, 0, 0, 0, 0, 64, 6, 0, 0, 172, 29, 56, 18, 10, 66, 66, 2}
	got := make(chan []byte, 1)
	sess.Endpoint().SetDownlink(func(buf []byte) {
		pkt := append([]byte(nil), buf...)
		select {
		case got <- pkt:
		default:
		}
	})
	if err := s.tunnel.SendDownlink(downlink); err != nil {
		t.Fatalf("下行发送失败: %v", err)
	}

	select {
	case pkt := <-got:
		if len(pkt) != len(downlink) {
			t.Errorf("下行包长度 = %d，期望 %d", len(pkt), len(downlink))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("承载侧没有收到下行包")
	}

	// 取消上下文后必须立刻收敛，并且两条流都要关掉。
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ctx 取消后 Run 没有返回")
	}
}

// 回归：任一条流失败时，另一条流也必须结束，不能留下永久阻塞的 goroutine
// 和没人关闭的连接。
func TestSessionRunClosesBothStreamsOnFailure(t *testing.T) {
	s := newScript(t)
	// 上行流握手续被拒，Run 应当立即返回。
	s.tunnel.RejectStream(0x05, ControlShutdown)
	sess := connectedSession(t, s)

	before := runtimeGoroutines()
	err := sess.Run(context.Background())
	if err == nil {
		t.Fatal("流被拒时 Run 必须返回错误")
	}
	if !strings.Contains(err.Error(), "上行流") {
		t.Errorf("错误信息应指明是哪条流: %v", err)
	}

	// 等一小会儿，让关闭动作传播到假服务端。
	time.Sleep(50 * time.Millisecond)
	after := runtimeGoroutines()
	if after > before+2 {
		t.Errorf("Run 返回后 goroutine 数从 %d 涨到 %d，疑似泄漏", before, after)
	}
}

// 回归：旧实现收到第一条流的错误后只是把回调置空，
// 另一条阻塞在写上的 goroutine 永远不会退出，连接也不会关闭。
func TestSessionRunClosesStreamsWhenRecvFails(t *testing.T) {
	s := newScript(t)
	sess := connectedSession(t, s)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- sess.Run(ctx) }()

	if err := s.tunnel.WaitRecvStream(2 * time.Second); err != nil {
		t.Fatal(err)
	}

	// 关闭服务端侧的连接，模拟隧道中途断开。
	s.tunnel.CloseRecvStream()

	select {
	case err := <-done:
		if err == nil {
			t.Error("下行流断开后 Run 应返回错误")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("下行流断开后 Run 没有返回")
	}
}

// 回归：Run 每一轮都会新建两条流，返回时必须关掉并摘出登记表。
//
// 以前三条返回路径都不关（注释却写着"不留任何连接"），RunWithRetry
// 每轮泄漏一组连接，直到整个会话结束。
func TestSessionRunReleasesStreamsOnReturn(t *testing.T) {
	s := newScript(t)
	sess := connectedSession(t, s)
	closedBefore := s.tunnel.Stats().Closed

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sess.Run(ctx) }()
	if err := s.tunnel.WaitRecvStream(2 * time.Second); err != nil {
		t.Fatal(err)
	}
	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("ctx 取消后 Run 没有返回")
	}

	// 假服务端要收到两条流的关闭（等一小会儿让关闭传播过去）。
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && s.tunnel.Stats().Closed < closedBefore+2 {
		time.Sleep(10 * time.Millisecond)
	}
	if got := s.tunnel.Stats().Closed; got < closedBefore+2 {
		t.Errorf("Run 返回后只关掉了 %d 条流，应为 2 条", got-closedBefore)
	}

	sess.mu.Lock()
	left := len(sess.streams)
	sess.mu.Unlock()
	if left != 0 {
		t.Errorf("Run 返回后登记表里还剩 %d 条流", left)
	}
}

// 终止性的控制码不该触发重试：反复重试会让账号进入被拒状态。
func TestRunWithRetryStopsOnTerminalControlCode(t *testing.T) {
	s := newScript(t)
	s.tunnel.RejectStream(0x06, ControlShutdown)
	sess := connectedSession(t, s)

	start := time.Now()
	err := sess.RunWithRetry(context.Background(), RetryPolicy{Attempts: 4, Base: time.Millisecond, Max: 5 * time.Millisecond})
	if err == nil {
		t.Fatal("终止性错误必须返回")
	}
	if time.Since(start) > time.Second {
		t.Errorf("终止性错误不该退避重试，耗时 %s", time.Since(start))
	}
	var ctrl *ControlError
	if !errors.As(err, &ctrl) {
		t.Errorf("期望 ControlError，实际 %T", err)
	}
}

// 可重试的错误在 ctx 取消后要立刻停下，不能睡满退避。
func TestRunWithRetryAbortsOnContextCancel(t *testing.T) {
	s := newScript(t)
	s.tunnel.RejectStream(0x06, ControlServerReset) // 可重试
	sess := connectedSession(t, s)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- sess.RunWithRetry(ctx, RetryPolicy{Attempts: 10, Base: time.Hour, Max: time.Hour})
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("期望 context.Canceled，实际 %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("退避睡眠没有响应 ctx 取消")
	}
}

// CheckTunnel 用完必须关闭连接：旧实现把它丢掉了，每次探测泄漏一条连接。
func TestCheckTunnelClosesConnection(t *testing.T) {
	s := newScript(t)
	sess := connectedSession(t, s)

	if err := sess.CheckTunnel(context.Background()); err != nil {
		t.Fatalf("握手检查失败: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if s.tunnel.Stats().Closed > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("握手检查没有关闭连接")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// 隧道端点会被隧道协程和承载协程并发访问，必须没有数据竞争。
func TestEndpointConcurrentUse(t *testing.T) {
	ep := NewEndpoint()
	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if err := ep.Send([]byte{1, 2, 3}); err != nil && !errors.Is(err, ErrNoUplink) {
					t.Errorf("Send 返回意外错误: %v", err)
					return
				}
				ep.Deliver([]byte{4, 5, 6})
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				ep.SetUplink(func([]byte) error { return nil })
				ep.ClearUplink()
				ep.SetDownlink(func([]byte) {})
			}
		}()
	}

	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// waitUplinkReady 等待上行通道建立。
func waitUplinkReady(ep *TunnelEndpoint, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ep.HasUplink() {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return errors.New("等待上行通道建立超时")
}
