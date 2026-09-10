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

// Trace 返回本次连接的阶段记录。
func (s *Session) Trace() *Trace { return s.trace }

// QueryConn 返回 query-ip 建立的连接。它由 Session 持有，调用方不应关闭。
func (s *Session) QueryConn() net.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.queryConn
}

// track 登记运行期连接，供 Close 统一关闭。
func (s *Session) track(conn net.Conn) {
	s.mu.Lock()
	s.streams = append(s.streams, conn)
	s.mu.Unlock()
}

func (s *Session) setRunCancel(cancel context.CancelFunc) {
	s.mu.Lock()
	s.runCancel = cancel
	s.mu.Unlock()
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
	s.setRunCancel(cancel)
	defer func() {
		s.setRunCancel(nil)
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
		return &StreamError{Direction: "下行流建立", Err: err}
	}
	s.track(rx)

	sink := newUplinkSink(tx)
	s.ep.SetUplink(sink.Write)
	defer s.ep.ClearUplink()

	// ctx 取消时主动关闭两条连接，让下面阻塞的读写立刻返回。
	stop := context.AfterFunc(ctx, func() {
		rx.Close()
		tx.Close()
	})
	defer stop()

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

// RunWithRetry 反复调用 Run，按 RetryPolicy 退避重连。
//
// 终止性错误（ControlError 里不可重试的控制码）立刻返回：
// 继续重试只会被服务端继续拒绝，还会把账号打进限流状态。
func (s *Session) RunWithRetry(ctx context.Context, policy RetryPolicy) error {
	if policy.Attempts < 1 || policy.Base <= 0 || policy.Max <= 0 {
		policy = DefaultRetryPolicy()
	}
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
