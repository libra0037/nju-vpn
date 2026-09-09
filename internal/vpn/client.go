package vpn

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

	"njuvpn/internal/dial"
)

// DialFunc 与 net.Dialer.Dial 的签名一致，由 internal/dial 提供。
type DialFunc = dial.DialFunc

// Client 持有到校园 VPN 服务端的出站连接方式。
//
// 所有连接都经由这里的 dialFn 建立，因此"是否走代理"只在构造时决定一次。
type Client struct {
	server string
	// dialAddr 非空时，所有 TCP 连接都连到这里，而协议层仍用 server
	// 生成 Host 头与 SNI。用于本机 DNS 解析不了服务端域名的情况。
	dialAddr string
	dialFn   DialFunc
}

// NewClient 构造一个客户端。server 形如 "vpn.example.edu:443"。
// dialFn 为 nil 时直连。
func NewClient(server string, dialFn DialFunc) *Client {
	if dialFn == nil {
		dialFn, _ = dial.New("")
	}
	return &Client{server: server, dialFn: dialFn}
}

// Server 返回 "host:port" 形式的目标地址。
func (c *Client) Server() string { return c.server }

// WithDialAddr 让连接目标指向 addr（形如 "202.119.32.69:443"），
// 但协议层继续使用原 server。返回自身以便链式调用。
func (c *Client) WithDialAddr(addr string) *Client {
	c.dialAddr = addr
	return c
}

// Dial 建立一条到服务端的 TCP 连接。
func (c *Client) Dial() (net.Conn, error) {
	return c.dialFn("tcp", c.dialTarget())
}

// dialTarget 返回实际要连接的地址。
func (c *Client) dialTarget() string {
	if c.dialAddr != "" {
		return c.dialAddr
	}
	return c.server
}

// httpClient 返回走同一出站路径的 HTTP 客户端。
// 校园服务端用自签证书，这里关掉校验，与旧实现一致。
func (c *Client) httpClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// 只替换服务端自身的地址；其它地址按原样拨号。
				if addr == c.server {
					addr = c.dialTarget()
				}
				return c.dialFn(network, addr)
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}
