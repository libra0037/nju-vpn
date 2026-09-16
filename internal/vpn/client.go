package vpn

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/libra0037/nju-vpn/internal/dial"
)

// DialFunc 与 net.Dialer.Dial 的签名一致，由 internal/dial 提供。
type DialFunc = dial.DialFunc

// TLSDialFunc 建立一条 TLS 连接。
//
// 生产实现用 uTLS（隧道方向是刻意畸形的 ClientHello）；测试可以注入
// 内存管道，从而在没有校园网的情况下覆盖协议层逻辑。
type TLSDialFunc func(ctx context.Context) (net.Conn, error)

// Timeouts 是各阶段的超时。
//
// 旧实现里 HTTP 客户端没有 Timeout，服务端"收下请求不回包"就能把
// 服务进程永久挂住——而那条路径正是在持锁状态下调用的。
type Timeouts struct {
	// HTTP 是单个 portal 请求的总超时。
	HTTP time.Duration
	// Handshake 是隧道握手、query-ip 等阶段的超时。
	Handshake time.Duration
}

// DefaultTimeouts 是各阶段的默认超时。
func DefaultTimeouts() Timeouts {
	return Timeouts{HTTP: 30 * time.Second, Handshake: 20 * time.Second}
}

// Options 是构造 Client 的参数，除 Server 外都可留空。
type Options struct {
	// Server 是服务端地址，形如 "vpn.example.edu:443"。协议层用它生成 Host 头。
	Server string
	// DialAddr 非空时所有 TCP 连接都连到这里，协议层仍用 Server。
	DialAddr string
	// Dial 是 TCP 层拨号函数（含代理）。为空时直连。
	Dial DialFunc
	// PortalTLS 建立 portal 接口用的标准 TLS 连接。为空时用 uTLS HelloGolang。
	PortalTLS TLSDialFunc
	// TunnelTLS 建立隧道用的 TLS 连接。为空时用刻意畸形的 ClientHello。
	TunnelTLS TLSDialFunc
	// HTTP 覆盖 portal 请求使用的 HTTP 客户端。为空时按 Dial 构造。
	HTTP *http.Client
	// Timeouts 覆盖默认超时。
	Timeouts Timeouts
}

// Client 持有到校园 VPN 服务端的出站连接方式。
//
// 所有连接都经由这里的 dialFn 建立，因此"是否走代理"只在构造时决定一次。
type Client struct {
	server   string
	dialAddr string
	dialFn   DialFunc

	portalTLS TLSDialFunc
	tunnelTLS TLSDialFunc
	http      *http.Client
	timeouts  Timeouts
}

// New 按 Options 构造客户端。
func New(opts Options) *Client {
	if opts.Dial == nil {
		opts.Dial, _ = dial.New("")
	}
	t := opts.Timeouts
	if t.HTTP <= 0 {
		t.HTTP = DefaultTimeouts().HTTP
	}
	if t.Handshake <= 0 {
		t.Handshake = DefaultTimeouts().Handshake
	}

	c := &Client{
		server:   opts.Server,
		dialAddr: opts.DialAddr,
		dialFn:   opts.Dial,
		timeouts: t,
	}
	if opts.PortalTLS != nil {
		c.portalTLS = opts.PortalTLS
	} else {
		c.portalTLS = c.dialPortalTLS
	}
	if opts.TunnelTLS != nil {
		c.tunnelTLS = opts.TunnelTLS
	} else {
		c.tunnelTLS = c.dialTunnelTLS
	}
	if opts.HTTP != nil {
		c.http = opts.HTTP
	} else {
		c.http = c.newHTTPClient()
	}
	return c
}

// DialContext 建立 TCP 连接，ctx 取消时放弃等待。
func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	return dialContext(ctx, c.dialFn, "tcp", c.dialTarget())
}

// dialContext 调一次拨号函数，并在 ctx 取消时放弃等待。
//
// 底层拨号函数没有 ctx 参数（要兼容代理实现），所以取消后由一个
// 清理协程等待拨号返回并关闭连接——底层拨号自身有超时，不会永久泄漏。
func dialContext(ctx context.Context, dialFn DialFunc, network, addr string) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := dialFn(network, addr)
		ch <- result{conn: conn, err: err}
	}()

	select {
	case r := <-ch:
		return r.conn, r.err
	case <-ctx.Done():
		go func() {
			if r := <-ch; r.conn != nil {
				r.conn.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

// dialTarget 返回实际要连接的地址。
func (c *Client) dialTarget() string {
	if c.dialAddr != "" {
		return c.dialAddr
	}
	return c.server
}

// dialPortalTLS 建立 portal 接口用的普通 TLS 连接。
// 校园服务端用自签证书，这里关掉校验，与旧实现一致。
func (c *Client) dialPortalTLS(ctx context.Context) (net.Conn, error) {
	raw, err := c.DialContext(ctx)
	if err != nil {
		return nil, err
	}
	return &utlsPortalConn{UConn: utls.UClient(raw, &utls.Config{InsecureSkipVerify: true}, utls.HelloGolang)}, nil
}

// dialTunnelTLS 建立隧道用的 TLS 长连接。
//
// uTLS 构造一个刻意畸形的 ClientHello：服务端要求 TLS 1.1、RC4-SHA，
// 并靠一个以 L3IP 开头的 SessionId 把隧道流量和同端口的 Web 登录流量
// 区分开。缺任何一项，握手都会被拒。
func (c *Client) dialTunnelTLS(ctx context.Context) (net.Conn, error) {
	raw, err := c.DialContext(ctx)
	if err != nil {
		return nil, err
	}
	log.Printf("socket: connected to: %s", raw.RemoteAddr())

	conn := utls.UClient(raw, &utls.Config{InsecureSkipVerify: true}, utls.HelloCustom)

	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		raw.Close()
		return nil, err
	}
	conn.SetClientRandom(random)
	conn.SetTLSVers(tunnelHelloVersion, tunnelHelloVersion, []utls.TLSExtension{})
	conn.HandshakeState.Hello.Vers = tunnelHelloVersion
	conn.HandshakeState.Hello.CipherSuites = tunnelHelloCipherSuites()
	conn.HandshakeState.Hello.CompressionMethods = tunnelHelloCompression()
	conn.HandshakeState.Hello.SessionId = tunnelHelloSessionID()
	// 隧道方向不需要实现 sessionIDSource（SessionId 是客户端自己构造的），
	// 直接返回底层连接即可。
	return conn, nil
}

// 隧道 ClientHello 的畸形参数。这些值是与服务端的契约，改动前先看
// wire_format_test.go：任何一项变了，握手都会被拒。
const tunnelHelloVersion = utls.VersionTLS11

// tunnelHelloSessionID 返回隧道专用的 SessionId。服务端靠它是否以
// "L3IP" 开头来区分隧道流量与同端口的 Web 登录流量。
func tunnelHelloSessionID() []byte {
	const sessionIDLen = 32
	id := make([]byte, sessionIDLen)
	copy(id, "L3IP")
	return id
}

// tunnelHelloCipherSuites 返回隧道 ClientHello 的套件列表。
// RC4-SHA 是服务端唯一接受的套件。
func tunnelHelloCipherSuites() []uint16 {
	return []uint16{
		utls.TLS_RSA_WITH_RC4_128_SHA,
		utls.FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
	}
}

// tunnelHelloCompression 返回隧道 ClientHello 的压缩方法。
func tunnelHelloCompression() []uint8 { return []uint8{0} }

// newHTTPClient 返回走同一出站路径的 HTTP 客户端。
//
// 关键点：设了 Timeout，且 Transport 在 Client 的整个生命周期里复用
// （旧实现每次请求都新建一个 Transport，空闲连接没人回收）。
func (c *Client) newHTTPClient() *http.Client {
	dialFn := c.dialFn
	server := c.server
	dialTarget := c.dialTarget()
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// 只替换服务端自身的地址；其它地址按原样拨号。
			if addr == server {
				addr = dialTarget
			}
			// 走 ctx 感知的版本：portal 请求卡在拨号上时，stop 与
			// 退出路径要能立刻放弃，而不是干等 Transport 的超时。
			return dialContext(ctx, dialFn, network, addr)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: transport, Timeout: c.timeouts.HTTP}
}

// CloseIdleConnections 释放 HTTP Transport 里空闲的连接。
func (c *Client) CloseIdleConnections() {
	if c.http != nil {
		c.http.CloseIdleConnections()
	}
}
