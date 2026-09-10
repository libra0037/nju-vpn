package vpn

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	tls "github.com/refraction-networking/utls"
)

func DumpHex(buf []byte) {
	stdoutDumper := hex.Dumper(os.Stdout)
	defer stdoutDumper.Close()
	stdoutDumper.Write(buf)
}

// TLSConn 建立一条隧道用的 TLS 长连接。
func (client *Client) TLSConn() (*tls.UConn, error) {
	// dial vpn server
	dialConn, err := client.Dial()
	if err != nil {
		return nil, err
	}
	log.Println("socket: connected to: ", dialConn.RemoteAddr())

	// 用 uTLS 构造一个刻意畸形的 Client Hello：服务端要求 TLS 1.1、
	// RC4-SHA 套件，并靠一个特殊 SessionId 把隧道流量和同端口的 Web 登录
	// 流量区分开。缺任何一项，握手都会被拒。
	conn := tls.UClient(dialConn, &tls.Config{InsecureSkipVerify: true}, tls.HelloCustom)

	random := make([]byte, 32)
	rand.Read(random) // Ignore the err
	conn.SetClientRandom(random)
	conn.SetTLSVers(tls.VersionTLS11, tls.VersionTLS11, []tls.TLSExtension{})
	conn.HandshakeState.Hello.Vers = tls.VersionTLS11
	conn.HandshakeState.Hello.CipherSuites = []uint16{tls.TLS_RSA_WITH_RC4_128_SHA, tls.FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV}
	conn.HandshakeState.Hello.CompressionMethods = []uint8{0}
	conn.HandshakeState.Hello.SessionId = []byte{'L', '3', 'I', 'P', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	log.Println("tls: connected to: ", conn.RemoteAddr())

	return conn, nil
}

// ProbeTunnel 走完整的隧道握手，然后立刻关闭，用来验证协议可用性。
// 它不建立任何数据通路，也不会长期占用服务端资源。
func (client *Client) ProbeTunnel(token *[48]byte, ipRev *[4]byte, debug bool) error {
	_, err := client.streamHandshake(token, ipRev, streamRecv, debug)
	return err
}

// streamKind 区分隧道里的两个方向。
type streamKind byte

const (
	streamRecv streamKind = 0x01 // 下行：校园网 -> 本机
	streamSend streamKind = 0x02 // 上行：本机 -> 校园网
)

func (k streamKind) String() string {
	if k == streamRecv {
		return "recv"
	}
	return "send"
}

// streamHandshake 打开一条流并完成握手，返回可用的连接。
func (client *Client) streamHandshake(token *[48]byte, ipRev *[4]byte, kind streamKind, debug bool) (*tls.UConn, error) {
	conn, err := client.TLSConn()
	if err != nil {
		return nil, err
	}

	// 0x06 请求下行流，0x05 请求上行流。
	opcode := byte(0x06)
	if kind == streamSend {
		opcode = 0x05
	}

	message := []byte{opcode, 0x00, 0x00, 0x00}
	message = append(message, token[:]...)
	message = append(message, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)
	message = append(message, ipRev[:]...)

	n, err := conn.Write(message)
	if err != nil {
		conn.Close()
		return nil, err
	}
	log.Printf("%s handshake: wrote %d bytes", kind, n)
	if debug {
		DumpHex(message[:n])
	}

	reply := make([]byte, 1500)
	n, err = conn.Read(reply)
	if err != nil {
		conn.Close()
		return nil, err
	}
	log.Printf("%s handshake: read %d bytes", kind, n)
	if debug {
		DumpHex(reply[:n])
	}

	if reply[0] != byte(kind) {
		conn.Close()
		// 服务端用控制码说明拒绝原因，走同一套可重试判断。
		return nil, &ControlError{Code: reply[0], Context: fmt.Sprintf("%s 流握手被拒绝", kind)}
	}
	return conn, nil
}

func (client *Client) QueryIp(token *[48]byte, debug bool) ([]byte, *tls.UConn, error) {
	conn, err := client.TLSConn()
	if err != nil {
		return nil, nil, err
	}
	// defer conn.Close()
	// Query IP conn CAN NOT be closed, otherwise tx/rx handshake will fail

	// QUERY IP PACKET
	message := []byte{0x00, 0x00, 0x00, 0x00}
	message = append(message, token[:]...)
	message = append(message, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff}...)

	n, err := conn.Write(message)
	if err != nil {
		return nil, nil, err
	}
	log.Printf("query ip: wrote %d bytes", n)
	if debug {
		DumpHex(message[:n])
	}

	reply := make([]byte, 0x80)
	n, err = conn.Read(reply)
	if err != nil {
		return nil, nil, err
	}

	log.Printf("query ip: read %d bytes", n)
	if debug {
		DumpHex(reply[:n])
	}

	if reply[0] != 0x00 {
		log.Printf("query ip: 请求报文:")
		DumpHex(message)
		log.Printf("query ip: 首字节为 0x%02x，完整响应:", reply[0])
		DumpHex(reply[:n])
		return nil, nil, &ControlError{Code: reply[0], Context: "query-ip 被拒绝"}
	}

	return reply[4:8], conn, nil
}

func (client *Client) BlockRXStream(token *[48]byte, ipRev *[4]byte, ep *TunnelEndpoint, debug bool) error {
	conn, err := client.streamHandshake(token, ipRev, streamRecv, debug)
	if err != nil {
		return err
	}
	defer conn.Close()

	reply := make([]byte, 1500)
	for {
		n, err := conn.Read(reply)
		if err != nil {
			return err
		}

		ep.WriteTo(reply[:n])

		if debug {
			log.Printf("recv: read %d bytes", n)
			DumpHex(reply[:n])
		}
	}
}

func (client *Client) BlockTXStream(token *[48]byte, ipRev *[4]byte, ep *TunnelEndpoint, debug bool) error {
	conn, err := client.streamHandshake(token, ipRev, streamSend, debug)
	if err != nil {
		return err
	}
	defer conn.Close()

	errCh := make(chan error, 1)

	ep.OnRecv = func(buf []byte) {
		var n, err = conn.Write(buf)
		if err != nil {
			// 非阻塞发送，避免同时有多个写失败时阻塞在通道上。
			select {
			case errCh <- err:
			default:
			}
			return
		}

		if debug {
			log.Printf("send: wrote %d bytes", n)
			DumpHex([]byte(buf[:n]))
		}
	}
	defer func() { ep.OnRecv = nil }()

	return <-errCh
}

// 重试参数。服务端的控制码区分了能否重试：
//
//	3 ServerReset / 5 IpBusy —— 暂时性，值得退避重试；
//	8 Shutdown / 9 IpConflict / 14 IpKick —— 终止性，重试只会继续被拒，
//	而且密集重试会让账号进入长时间被拒的状态。
const (
	streamRetryLimit = 4
	streamRetryBase  = 2 * time.Second
	streamRetryMax   = 30 * time.Second
)

// StreamError 表示某条数据流（收或发）终止。
type StreamError struct {
	// Direction 是 "recv" 或 "send"。
	Direction string
	Err       error
}

func (e *StreamError) Error() string {
	return fmt.Sprintf("%s 流失败: %v", e.Direction, e.Err)
}

func (e *StreamError) Unwrap() error { return e.Err }

// StartProtocol 建立收、发两条数据流并阻塞转发，直到任一条终止。
//
// 调用方应在单独的 goroutine 中运行它，并根据返回的错误更新服务状态。
// 与旧实现不同，这里不再在重试耗尽后 panic——服务进程需要能感知失败，
// 而不是整体崩溃。
func (client *Client) StartProtocol(endpoint *TunnelEndpoint, token *[48]byte, ipRev *[4]byte, debug bool) error {
	errCh := make(chan *StreamError, 2)

	go func() {
		errCh <- &StreamError{Direction: "recv", Err: client.runStream(streamRecv, token, ipRev, endpoint, debug)}
	}()
	// 发方向的真实错误由 OnRecv 回填，见 BlockTXStream。
	go func() {
		errCh <- &StreamError{Direction: "send", Err: client.runStream(streamSend, token, ipRev, endpoint, debug)}
	}()

	first := <-errCh
	// 一条断了，另一条也就没有意义了。清掉回调，避免继续往已关闭的连接写。
	endpoint.OnRecv = nil
	return first
}

// runStream 带退避地反复建立一条流，正常返回时按 error 处理。
func (client *Client) runStream(kind streamKind, token *[48]byte, ipRev *[4]byte, ep *TunnelEndpoint, debug bool) error {
	var lastErr error
	for attempt := 0; attempt <= streamRetryLimit; attempt++ {
		if attempt > 0 {
			delay := retryDelay(attempt)
			log.Printf("%s 流第 %d 次重试，%s 后重连（上次错误: %v）", kind, attempt, delay, lastErr)
			time.Sleep(delay)
		}

		var err error
		if kind == streamRecv {
			err = client.BlockRXStream(token, ipRev, ep, debug)
		} else {
			err = client.BlockTXStream(token, ipRev, ep, debug)
		}
		lastErr = err
		if err == nil {
			return nil
		}

		// 终止性错误直接放弃，避免把账号打进被拒状态。
		var ctrl *ControlError
		if errors.As(err, &ctrl) && !ctrl.Retryable() {
			return err
		}
	}
	return fmt.Errorf("重试 %d 次后仍未恢复: %w", streamRetryLimit, lastErr)
}

// retryDelay 返回第 attempt 次重试前的等待时长（attempt 从 1 开始），
// 按 2 秒起步指数增长，上限 30 秒。
func retryDelay(attempt int) time.Duration {
	d := streamRetryBase << (attempt - 1)
	if d <= 0 || d > streamRetryMax {
		return streamRetryMax
	}
	return d
}
