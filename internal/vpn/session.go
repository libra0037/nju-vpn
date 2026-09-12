package vpn

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// logoutTimeout 限制登出请求的总时长。
// 登出会出现在进程退出路径上，网络不通时不能把进程卡住。
const logoutTimeout = 10 * time.Second

// Session 是一次登录会话的全部资源：TwfID、隧道 token、query-ip 连接，
// 以及运行期建立的收发两条流。
//
// 所有权规则很简单：谁调用 Connect 拿到 Session，谁负责调用 Close。
// Close 幂等，并且会无条件尝试通知服务端登出——服务端对同一账号只允许
// 一个客户端，残留会话会让后续建隧道被拒。
type Session struct {
	client *Client
	twfID  string
	token  [streamTokenLen]byte
	ip     net.IP
	ipRev  [4]byte
	debug  bool
	trace  *Trace
	ep     *TunnelEndpoint

	mu        sync.Mutex
	queryConn net.Conn
	streams   []net.Conn
	runCancel context.CancelFunc

	closeOnce  sync.Once
	logoutOnce sync.Once
	logoutErr  error
}

// TwfID 返回当前会话标识。
func (s *Session) TwfID() string { return s.twfID }

// ClientIP 返回校园网分配到的地址。
func (s *Session) ClientIP() string {
	if s.ip == nil {
		return ""
	}
	return s.ip.String()
}

// Endpoint 返回承载侧使用的隧道端点。
func (s *Session) Endpoint() *TunnelEndpoint { return s.ep }

// track 登记运行期连接，供 Close 统一关闭。
func (s *Session) track(conn net.Conn) {
	s.mu.Lock()
	s.streams = append(s.streams, conn)
	s.mu.Unlock()
}

// untrack 摘掉运行期连接。
//
// RunWithRetry 每轮都会重新建两条流，不摘掉的话列表会随着重试一直涨。
func (s *Session) untrack(conns ...net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.streams[:0]
	for _, c := range s.streams {
		drop := false
		for _, d := range conns {
			if c == d {
				drop = true
				break
			}
		}
		if !drop {
			kept = append(kept, c)
		}
	}
	s.streams = kept
}

// pushRunCancel 登记"当前运行的取消函数"，返回还原函数。
//
// 登记是嵌套的：RunWithRetryNotify 先登记整段重试那个（退避等待也要能被
// 唤醒），Run 每轮再登记自己那个（要打断阻塞中的读写），退出时把外层那个
// 放回去。以前 Run 退出时直接把字段清成 nil，于是退避窗口里 CloseLocal
// 拿不到任何 cancel：会话明明已经断开，循环还在睡，睡醒之后又在已关闭的
// 会话上重建两条流，一路泄漏到会话结束。
func (s *Session) pushRunCancel(cancel context.CancelFunc) func() {
	s.mu.Lock()
	prev := s.runCancel
	s.runCancel = cancel
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		s.runCancel = prev
		s.mu.Unlock()
	}
}

func (s *Session) takeRunCancel() context.CancelFunc {
	s.mu.Lock()
	defer s.mu.Unlock()
	cancel := s.runCancel
	s.runCancel = nil
	return cancel
}

// CheckTunnel 建立一条下行流并立刻关闭，用来验证流握手是否被接受。
//
// 旧实现在这里丢弃了连接，每次探测泄漏一条 TLS 连接和服务端一条流。
func (s *Session) CheckTunnel(ctx context.Context) error {
	conn, err := s.client.openStream(ctx, s.token, s.ipRev, streamRecv, s.debug)
	if err != nil {
		return err
	}
	return conn.Close()
}

// Run 建立收发两条流并开始转发，直到任一条失败或 ctx 被取消。
//
// 返回后不会再留下任何 goroutine 或连接：任一条流出错都会关闭另一条，
// 而关闭连接会让阻塞中的 Read/Write 立刻返回。
func (s *Session) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	restore := s.pushRunCancel(cancel)
	defer func() {
		restore()
		cancel()
	}()

	tx, err := s.client.openStream(ctx, s.token, s.ipRev, streamSend, s.debug)
	if err != nil {
		return &StreamError{Direction: "上行流建立", Err: err}
	}
	s.track(tx)

	rx, err := s.client.openStream(ctx, s.token, s.ipRev, streamRecv, s.debug)
	if err != nil {
		tx.Close()
		// 这条路径不走下面的 defer（defer 要两条流都建好才装上），
		// 漏摘的话登记表会一直留着这条已关闭的上行流，直到会话结束。
		s.untrack(tx)
		return &StreamError{Direction: "下行流建立", Err: err}
	}
	s.track(rx)

	sink := newUplinkSink(tx)
	s.ep.SetUplink(sink.Write)
	// ctx 取消时主动关闭两条连接，让下面阻塞的读写立刻返回。
	stop := context.AfterFunc(ctx, func() {
		rx.Close()
		tx.Close()
	})
	// 收尾顺序是有讲究的（LIFO 展开）：先注销 AfterFunc、再摘上行回调，
	// 最后关流。反过来的话，先关流会让一个正在写（被背压挡住）的 Send
	// 卡在旧实现那把锁上，ClearUplink 与 dev.Close() 就跟着一起挂住，
	// 登出永远发不出去（真机出现过：stop 不返回，只能强杀进程）。
	//
	// 这个 defer 同时负责注释开头那条承诺：返回时不留任何连接与 goroutine。
	// RunWithRetry 每一轮都会调用本函数，漏一次就是一组连接堆到会话结束。
	defer func() {
		stop()
		s.ep.ClearUplink()
		tx.Close()
		rx.Close()
		s.untrack(tx, rx)
	}()

	recvErr := make(chan error, 1)
	go func() { recvErr <- s.readLoop(rx) }()

	select {
	case err := <-recvErr:
		return &StreamError{Direction: "下行流", Err: err}
	case <-sink.Done():
		return &StreamError{Direction: "上行流", Err: sink.Err()}
	case <-ctx.Done():
		return ctx.Err()
	}
}

// RunWithRetryNotify 反复调用 Run，按 RetryPolicy 退避重连，并在每次
// 重连前回调通知。
//
// 调用方（服务层）靠它把"正在重连"告诉用户：重连期间隧道是断的，
// 而状态如果一直显示 up，用户会以为链路正常、只是"网慢"。
//
// 终止性错误（ControlError 里不可重试的控制码）立刻返回：
// 继续重试只会被服务端继续拒绝，还会把账号打进限流状态。
func (s *Session) RunWithRetryNotify(ctx context.Context, policy RetryPolicy, onRetry func(attempt int, err error)) error {
	if policy.Attempts < 1 || policy.Base <= 0 || policy.Max <= 0 {
		policy = DefaultRetryPolicy()
	}
	// 整段重试（含退避等待）挂在同一个 ctx 上：CloseLocal 一取消，
	// 正在睡的退避立刻醒过来。
	ctx, cancel := context.WithCancel(ctx)
	restore := s.pushRunCancel(cancel)
	defer func() {
		restore()
		cancel()
	}()
	var lastErr error
	for attempt := 1; ; attempt++ {
		err := s.Run(ctx)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		lastErr = err
		if !retryable(err) {
			return err
		}
		if attempt > policy.Attempts {
			return fmt.Errorf("重试 %d 次后仍未恢复: %w", policy.Attempts, lastErr)
		}
		delay := policy.delay(attempt)
		log.Printf("隧道断开（第 %d 次）: %v，%s 后重连", attempt, err, delay)
		if onRetry != nil {
			onRetry(attempt, err)
		}
		if err := sleepCtx(ctx, delay); err != nil {
			return err
		}
	}
}

// readLoop 把下行包交给承载侧。
func (s *Session) readLoop(conn net.Conn) error {
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			s.ep.Deliver(buf[:n])
		}
		if err != nil {
			return err
		}
	}
}

// Close 释放本地资源并通知服务端登出。可安全重复调用。
func (s *Session) Close(ctx context.Context) error {
	s.closeLocal()
	return s.logout(ctx)
}

// CloseLocal 只释放本地资源，不通知服务端登出。
//
// 用于"探测完但想保留服务端会话"这类场景（njuvpn probe -keep）：
// 进程退出后本地连接自然消失，但服务端的名额仍然占着，
// 所以调用方必须自己记住 TwfID。
func (s *Session) CloseLocal() { s.closeLocal() }

// closeLocal 关闭本地资源，不涉及网络。
func (s *Session) closeLocal() {
	s.closeOnce.Do(func() {
		if cancel := s.takeRunCancel(); cancel != nil {
			cancel()
		}
		s.mu.Lock()
		streams := s.streams
		s.streams = nil
		query := s.queryConn
		s.queryConn = nil
		s.mu.Unlock()

		for _, c := range streams {
			c.Close()
		}
		if query != nil {
			query.Close()
		}
		if s.ep != nil {
			s.ep.ClearUplink()
		}
	})
}

// logout 通知服务端注销会话，只会真正执行一次。
func (s *Session) logout(ctx context.Context) error {
	s.logoutOnce.Do(func() {
		if s.twfID == "" || s.client == nil {
			return
		}
		// 退出路径上 ctx 可能已经被取消，那种情况下登出也得照做。
		base := ctx
		if base == nil || base.Err() != nil {
			base = context.Background()
		}
		logoutCtx, cancel := context.WithTimeout(base, logoutTimeout)
		defer cancel()

		err := s.client.Logout(logoutCtx, s.twfID)
		switch {
		case err == nil:
			log.Printf("已通知服务端注销会话")
		case errors.Is(err, ErrLogoutNoSession):
			log.Printf("服务端已无此会话，无需登出")
		default:
			log.Printf("登出未成功: %v", err)
		}
		s.logoutErr = err
	})
	return s.logoutErr
}

// sleepCtx 是可取消的等待。
func sleepCtx(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
