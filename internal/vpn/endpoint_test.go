package vpn

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// TestRunReturnsWhileUplinkWriteBlocks 是 A1 的回归测试。
//
// 场景：客户端有包要发，上行写被对端背压挡住（数据阶段没有写 deadline，
// 这是真实可能发生的）；此时下行流出错，Run 走返回路径。
//
// 旧实现的收尾顺序是 stop() → ClearUplink() → 关两条流，而 ClearUplink
// 要拿 Send 持有的读锁，于是 Run 永久卡住：不重连、不报断开、status 停在
// up，teardown 里的 dev.Close() 也跟着挂住，登出永远发不出去——只能强杀
// 进程，服务端名额要等它自己超时才释放。
//
// 现在收尾是"先摘回调、再关流"，而回调的注册/注销是原子的，不等写入结束。
func TestRunReturnsWhileUplinkWriteBlocks(t *testing.T) {
	txClient, txServer := net.Pipe()
	rxClient, rxServer := net.Pipe()

	calls := 0
	c := New(Options{
		Server:   "vpn.example.edu:443",
		Timeouts: Timeouts{HTTP: time.Second, Handshake: 2 * time.Second},
		TunnelTLS: func(ctx context.Context) (net.Conn, error) {
			calls++
			if calls == 1 {
				return txClient, nil // 上行流先建
			}
			return rxClient, nil // 下行流
		},
	})

	// 服务端侧：读握手、回 ack。之后上行不再读任何数据，让客户端的写阻塞。
	ack := func(conn net.Conn, b byte) {
		head := make([]byte, 64)
		if _, err := io.ReadFull(conn, head); err != nil {
			t.Logf("读握手失败: %v", err)
			return
		}
		if _, err := conn.Write([]byte{b}); err != nil {
			t.Logf("写 ack 失败: %v", err)
		}
	}
	go ack(txServer, 0x02)
	go func() {
		ack(rxServer, 0x01)
		time.Sleep(200 * time.Millisecond)
		rxServer.Close() // 下行断开，Run 走返回路径
	}()

	sess := &Session{client: c, ep: NewEndpoint()}
	runDone := make(chan error, 1)
	go func() { runDone <- sess.Run(context.Background()) }()

	deadline := time.Now().Add(3 * time.Second)
	for !sess.ep.HasUplink() {
		if time.Now().After(deadline) {
			t.Fatal("上行回调没有注册")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// 一个卡在写里的包：net.Pipe 是同步的，服务端不读就永远写不完。
	sendDone := make(chan error, 1)
	go func() { sendDone <- sess.ep.Send([]byte("blocked")) }()
	time.Sleep(100 * time.Millisecond)
	select {
	case err := <-sendDone:
		t.Fatalf("这一次 Send 不该已经返回: %v", err)
	default:
	}

	// 关键断言：下行断开之后 Run 必须很快返回。
	select {
	case err := <-runDone:
		if err == nil {
			t.Fatal("下行断开后 Run 应返回错误")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run 卡住了：上行写阻塞时收尾拿不到锁（A1 回归）")
	}

	// 收尾之后上行回调必须已经摘掉，且注销立刻返回。
	if sess.ep.HasUplink() {
		t.Fatal("Run 返回后上行回调应已注销")
	}
	done := make(chan struct{})
	go func() {
		sess.ep.ClearUplink()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("注销上行回调被阻塞的写入挡住了")
	}
}

// TestEndpointClearDoesNotWaitForBlockedCallback 直接钉住这条不变量：
// 注销不等正在进行的回调结束。
func TestEndpointClearDoesNotWaitForBlockedCallback(t *testing.T) {
	ep := NewEndpoint()
	release := make(chan struct{})
	entered := make(chan struct{})
	ep.SetUplink(func([]byte) error {
		close(entered)
		<-release
		return nil
	})

	go func() { _ = ep.Send([]byte("x")) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("上行回调没有被调用")
	}

	done := make(chan struct{})
	go func() {
		ep.ClearUplink()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ClearUplink 被阻塞的回调挡住了")
	}

	// 摘掉之后新包立刻拿到 ErrNoUplink，不再进回调。
	if err := ep.Send([]byte("y")); err != ErrNoUplink {
		t.Fatalf("注销后应返回 ErrNoUplink，实际 %v", err)
	}
	close(release)
}
