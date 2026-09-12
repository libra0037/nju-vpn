package vpn

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

// DumpHex 打印报文的十六进制内容。
//
// 只在显式打开 debug 时调用：握手报文里含 token 与 TWFID，等价于凭据。
func DumpHex(buf []byte) {
	dumper := hex.Dumper(os.Stdout)
	defer dumper.Close()
	_, _ = dumper.Write(buf)
}

// streamKind 区分隧道里的两个方向。
type streamKind byte

const (
	streamRecv streamKind = 0x01 // 下行：校园网 -> 本机
	streamSend streamKind = 0x02 // 上行：本机 -> 校园网
)

func (k streamKind) String() string {
	if k == streamRecv {
		return "下行流"
	}
	return "上行流"
}

// openStream 建立一条数据流并完成握手。
//
// 返回的连接由调用方持有；每条失败路径都先关闭连接。
func (c *Client) openStream(ctx context.Context, token [streamTokenLen]byte, ipRev [4]byte, kind streamKind, debug bool) (net.Conn, error) {
	conn, err := c.tunnelTLS(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", kind, err)
	}
	// 握手阶段必须有超时，否则对端不回包就会永久挂住。
	if err := conn.SetDeadline(deadlineFrom(ctx, c.timeouts.Handshake)); err != nil {
		conn.Close()
		return nil, err
	}
	// deadline 只是上限，取消要能立刻生效。
	unwatch := watchCancel(ctx, conn)
	defer unwatch()

	// 0x06 请求下行流，0x05 请求上行流。
	opcode := byte(0x06)
	if kind == streamSend {
		opcode = 0x05
	}

	message := make([]byte, 0, 4+streamTokenLen+8+4)
	message = append(message, opcode, 0x00, 0x00, 0x00)
	message = append(message, token[:]...)
	message = append(message, make([]byte, 8)...)
	message = append(message, ipRev[:]...)

	n, err := conn.Write(message)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("%s: 发送握手: %w", kind, err)
	}
	log.Printf("%s handshake: wrote %d bytes", kind, n)
	if debug {
		DumpHex(message)
	}

	reply := make([]byte, 64)
	n, err = conn.Read(reply)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("%s: 读取握手回执: %w", kind, err)
	}
	if n == 0 {
		conn.Close()
		return nil, &ProtocolError{Step: kind.String(), Reason: "握手回执为空"}
	}
	if debug {
		log.Printf("%s handshake: read %d bytes", kind, n)
		DumpHex(reply[:n])
	}

	if reply[0] != byte(kind) {
		conn.Close()
		// 服务端用控制码说明拒绝原因，走同一套可重试判断。
		return nil, &ControlError{Code: reply[0], Context: fmt.Sprintf("%s握手被拒绝", kind)}
	}

	// 数据阶段不再设 deadline：长连接会长时间空闲，退出靠 ctx 取消或显式关闭。
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// queryIP 请求服务端分配一个校园网地址。
//
// 返回的连接必须保持打开到隧道握手完成，否则服务端会断开 i/o 流，
// 所以它是返回值的一部分，由调用方持有。失败路径一律关闭连接：
// 旧实现在失败时返回 (nil, nil, err)，调用方的清理代码永远是死代码。
func (c *Client) queryIP(ctx context.Context, token [streamTokenLen]byte, debug bool) (net.IP, net.Conn, error) {
	const step = "query-ip"

	conn, err := c.tunnelTLS(ctx)
	if err != nil {
		return nil, nil, err
	}
	owned := true
	defer func() {
		if owned {
			conn.Close()
		}
	}()

	if err := conn.SetDeadline(deadlineFrom(ctx, c.timeouts.Handshake)); err != nil {
		return nil, nil, err
	}
	unwatch := watchCancel(ctx, conn)
	defer unwatch()

	message := []byte{0x00, 0x00, 0x00, 0x00}
	message = append(message, token[:]...)
	message = append(message, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff}...)

	if _, err := conn.Write(message); err != nil {
		return nil, nil, fmt.Errorf("%s: 发送请求: %w", step, err)
	}
	if debug {
		DumpHex(message)
	}

	// 控制码只读 1 字节再看成功与否：被拒绝时服务端可能只回一个控制码就
	// 关连接，按"读满 4 字节"去读会把控制码一起丢掉，那次可重试的拒绝
	// 就变成了读失败（退避重试会白烧一轮配额）。
	head := make([]byte, 1)
	if _, err := io.ReadFull(conn, head); err != nil {
		return nil, nil, fmt.Errorf("%s: 读取响应: %w", step, err)
	}
	if head[0] != ControlSendIP {
		return nil, nil, &ControlError{Code: head[0], Context: "query-ip 被拒绝"}
	}
	// 成功时把剩下的读满（长度字段余下 3 字节 + 4 字节地址），而不是
	// "一次 Read 期望拿到整个 36 字节回执"：隧道是字节流，服务端一次写多少
	// 与我们一次读到多少没有必然关系。旧实现单次 Read 只拿到 4 字节时会把
	// 这次失败判成不可重试的协议错误，三次退避一次都没走。
	rest := make([]byte, 7)
	if _, err := io.ReadFull(conn, rest); err != nil {
		return nil, nil, fmt.Errorf("%s: 读取分配的地址: %w", step, err)
	}
	ip := net.IPv4(rest[3], rest[4], rest[5], rest[6])
	if debug {
		log.Printf("query ip: 控制码 %#x，分配地址 %s", head[0], ip)
		DumpHex(append(append([]byte(nil), head...), rest...))
	}
	// 数据阶段保持长连接，不设 deadline。
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, nil, err
	}
	owned = false
	return ip, conn, nil
}

// uplinkSink 把上行的 IP 包写进隧道，并记住第一次写失败。
//
// 上行方向平时没有读者，只有真的有包要发时才知道连接已经死了，
// 所以失败要靠写路径主动上报。
type uplinkSink struct {
	conn net.Conn

	mu   sync.Mutex
	err  error
	done chan struct{}
}

func newUplinkSink(conn net.Conn) *uplinkSink {
	return &uplinkSink{conn: conn, done: make(chan struct{})}
}

// Write 实现 TunnelEndpoint 需要的写入回调。
func (s *uplinkSink) Write(buf []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	if _, err := s.conn.Write(buf); err != nil {
		s.err = err
		close(s.done)
		return err
	}
	return nil
}

// Err 返回第一次写失败的原因。
func (s *uplinkSink) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Done 在第一次写失败时关闭。
func (s *uplinkSink) Done() <-chan struct{} { return s.done }

// StreamError 表示某条数据流终止。
type StreamError struct {
	Direction string
	Err       error
}

func (e *StreamError) Error() string { return e.Direction + "失败: " + e.Err.Error() }
func (e *StreamError) Unwrap() error { return e.Err }

// RetryPolicy 描述数据流断开后的重连策略。
//
// 服务端的控制码区分了能否重试：5(IpBusy) 值得退避重试；其余（3 ServerReset、
// 8 Shutdown、9 IpConflict、14 IpKick）都是终止性的，重试只会继续被拒，
// 密集重试还会让账号进入长时间被拒绝的状态。
type RetryPolicy struct {
	Attempts int
	Base     time.Duration
	Max      time.Duration
}

// DefaultRetryPolicy 是默认的重连策略。
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{Attempts: 4, Base: 2 * time.Second, Max: 30 * time.Second}
}

// delay 返回第 attempt 次重试前的等待时长（attempt 从 1 开始）。
func (p RetryPolicy) delay(attempt int) time.Duration {
	if attempt <= 0 {
		return 0
	}
	if attempt > 30 { // 防御移位溢出
		return p.Max
	}
	d := p.Base << (attempt - 1)
	if d <= 0 || d > p.Max {
		return p.Max
	}
	return d
}

// retryable 判断错误是否值得重试。
func retryable(err error) bool {
	var ctrl *ControlError
	if errors.As(err, &ctrl) {
		return ctrl.Retryable()
	}
	// 协议不符不会自愈：服务端回了预期之外的字节，重试只是白烧配额
	//（密集重试会把账号打进被拒状态）。
	var proto *ProtocolError
	if errors.As(err, &proto) {
		return false
	}
	return true
}
