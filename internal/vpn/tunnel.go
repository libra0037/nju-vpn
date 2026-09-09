package vpn

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"

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
		return nil, fmt.Errorf("unexpected %s handshake reply: 0x%02x", kind, reply[0])
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
		return nil, nil, fmt.Errorf("%w: 首字节 0x%02x，共 %d 字节", ErrServerBusy, reply[0], n)
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
			errCh <- err
			return
		}

		if debug {
			log.Printf("send: wrote %d bytes", n)
			DumpHex([]byte(buf[:n]))
		}
	}

	return <-errCh
}

func (client *Client) StartProtocol(endpoint *TunnelEndpoint, token *[48]byte, ipRev *[4]byte, debug bool) {
	RX := func() {
		counter := 0
		for counter < 5 {
			err := client.BlockRXStream(token, ipRev, endpoint, debug)
			if err != nil {
				log.Print("Error occurred while recv, retrying: " + err.Error())
			}
			counter += 1
		}
		panic("recv retry limit exceeded.")
	}

	go RX()

	TX := func() {
		counter := 0
		for counter < 5 {
			err := client.BlockTXStream(token, ipRev, endpoint, debug)
			if err != nil {
				log.Print("Error occurred while send, retrying: " + err.Error())
			}
			counter += 1
		}
		panic("send retry limit exceeded.")
	}

	go TX()
}

// ErrServerBusy 表示服务端拒绝了本次建连。
//
// 现象是收到一段固定长度的响应，首字节不是协议规定的 0x00，内容看起来像
// 服务端进程的内存（含小端栈指针），而且同一个 TwfID 短时间内反复建连时
// 必然出现。静置一段时间后同一请求就会成功，因此判定为服务端的并发限制。
var ErrServerBusy = errors.New("服务端暂时拒绝建连（同一会话建连过于频繁）")
