// Package dial 统一管理到校园 VPN 服务端的出站连接。
//
// 服务端可能只在校外可达，而本机可能在校内，因此所有连接都支持经由一个
// HTTP 代理（CONNECT 方法）建立。代理地址来自配置文件，不读环境变量，
// 避免服务进程的语义随环境漂移。
package dial

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const dialTimeout = 20 * time.Second

// DialFunc 与 net.Dialer.Dial 的签名一致。
type DialFunc func(network, address string) (net.Conn, error)

// New 返回一个拨号函数。proxy 为空时直连，否则经由代理。
//
// proxy 支持这几种写法：
//
//	""                          直连
//	http://127.0.0.1:7897       匿名 HTTP 代理
//	http://user:pass@host:port  带认证的 HTTP 代理
//	socks5://127.0.0.1:1080     SOCKS5 代理，目标域名交给代理解析
func New(proxy string) (DialFunc, error) {
	if proxy == "" {
		d := &net.Dialer{Timeout: dialTimeout}
		return d.Dial, nil
	}

	u, err := url.Parse(proxy)
	if err != nil {
		return nil, fmt.Errorf("解析代理地址 %q: %w", proxy, err)
	}

	switch u.Scheme {
	case "http", "https":
		return httpProxyDialer(u)
	case "socks5", "socks5h":
		return socks5ProxyDialer(u)
	case "":
		return nil, fmt.Errorf("代理地址 %q 缺少协议前缀，例如 http://127.0.0.1:7897", proxy)
	default:
		return nil, fmt.Errorf("不支持的代理协议 %q", u.Scheme)
	}
}

// httpProxyDialer 通过 HTTP 代理的 CONNECT 方法建到目标地址的隧道。
func httpProxyDialer(u *url.URL) (DialFunc, error) {
	// https 代理必须先建立 TLS 再发 CONNECT：否则 Proxy-Authorization
	// 里的 Basic 凭据是明文（旧实现就是这样把凭据写在裸 TCP 上的）。
	useTLS := u.Scheme == "https"
	host := u.Host
	if u.Port() == "" {
		if u.Scheme == "https" {
			host = net.JoinHostPort(u.Hostname(), "443")
		} else {
			host = net.JoinHostPort(u.Hostname(), "80")
		}
	}

	auth := ""
	if u.User != nil {
		pass, _ := u.User.Password()
		auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+pass))
	}

	return func(network, address string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, fmt.Errorf("HTTP 代理只支持 tcp，收到 %q", network)
		}

		conn, err := dialProxy(host, useTLS)
		if err != nil {
			return nil, err
		}

		if err := conn.SetDeadline(time.Now().Add(dialTimeout)); err != nil {
			conn.Close()
			return nil, err
		}

		req := "CONNECT " + address + " HTTP/1.1\r\nHost: " + address + "\r\n"
		if auth != "" {
			req += "Proxy-Authorization: " + auth + "\r\n"
		}
		req += "\r\n"

		if _, err := io.WriteString(conn, req); err != nil {
			conn.Close()
			return nil, fmt.Errorf("向代理发送 CONNECT: %w", err)
		}

		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("读取代理响应: %w", err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			conn.Close()
			return nil, fmt.Errorf("代理拒绝 CONNECT %s: %s", address, resp.Status)
		}

		if err := conn.SetDeadline(time.Time{}); err != nil {
			conn.Close()
			return nil, err
		}
		return &bufferedConn{Conn: conn, r: br}, nil
	}, nil
}

// socks5ProxyDialer 通过 SOCKS5 代理建连，目标地址以域名形式交给代理解析，
// 这样本机不需要能解析校园域名。
func socks5ProxyDialer(u *url.URL) (DialFunc, error) {
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "1080")
	}

	return func(network, address string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, fmt.Errorf("SOCKS5 代理只支持 tcp，收到 %q", network)
		}

		conn, err := (&net.Dialer{Timeout: dialTimeout}).Dial("tcp", host)
		if err != nil {
			return nil, fmt.Errorf("连接代理 %s: %w", host, err)
		}

		if err := conn.SetDeadline(time.Now().Add(dialTimeout)); err != nil {
			conn.Close()
			return nil, err
		}

		if err := socks5Handshake(conn, u, address); err != nil {
			conn.Close()
			return nil, err
		}

		if err := conn.SetDeadline(time.Time{}); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}, nil
}

func socks5Handshake(conn net.Conn, u *url.URL, address string) error {
	methods := []byte{0x00}
	if u.User != nil {
		methods = []byte{0x00, 0x02}
	}
	if _, err := conn.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		return fmt.Errorf("SOCKS5 问候: %w", err)
	}

	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("SOCKS5 问候响应: %w", err)
	}
	if reply[0] != 0x05 {
		return fmt.Errorf("SOCKS5 版本不匹配: %d", reply[0])
	}

	switch reply[1] {
	case 0x00:
	case 0x02:
		if u.User == nil {
			return fmt.Errorf("SOCKS5 代理要求认证，但代理地址里没有用户名")
		}
		pass, _ := u.User.Password()
		user := u.User.Username()
		if len(user) > 255 || len(pass) > 255 {
			return fmt.Errorf("SOCKS5 用户名或密码过长")
		}
		buf := []byte{0x01, byte(len(user))}
		buf = append(buf, user...)
		buf = append(buf, byte(len(pass)))
		buf = append(buf, pass...)
		if _, err := conn.Write(buf); err != nil {
			return fmt.Errorf("SOCKS5 认证: %w", err)
		}
		res := make([]byte, 2)
		if _, err := io.ReadFull(conn, res); err != nil {
			return fmt.Errorf("SOCKS5 认证响应: %w", err)
		}
		if res[1] != 0x00 {
			return fmt.Errorf("SOCKS5 认证失败")
		}
	case 0xff:
		return fmt.Errorf("SOCKS5 代理不接受任何认证方式")
	default:
		return fmt.Errorf("SOCKS5 代理选择了不支持的认证方式 %d", reply[1])
	}

	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("解析目标地址 %q: %w", address, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("解析目标端口 %q: %w", portStr, err)
	}

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("SOCKS5 请求: %w", err)
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return fmt.Errorf("SOCKS5 请求响应: %w", err)
	}
	if head[0] != 0x05 {
		return fmt.Errorf("SOCKS5 版本不匹配: %d", head[0])
	}
	if head[1] != 0x00 {
		return fmt.Errorf("SOCKS5 代理拒绝连接: %s", socks5Status(head[1]))
	}

	var skip int
	switch head[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return fmt.Errorf("SOCKS5 响应地址: %w", err)
		}
		skip = int(l[0])
	default:
		return fmt.Errorf("SOCKS5 未知地址类型 %d", head[3])
	}
	if _, err := io.ReadFull(conn, make([]byte, skip+2)); err != nil {
		return fmt.Errorf("SOCKS5 响应地址: %w", err)
	}
	return nil
}

func socks5Status(code byte) string {
	switch code {
	case 0x01:
		return "一般性失败"
	case 0x02:
		return "规则不允许"
	case 0x03:
		return "网络不可达"
	case 0x04:
		return "主机不可达"
	case 0x05:
		return "连接被拒绝"
	case 0x06:
		return "TTL 过期"
	case 0x07:
		return "命令不支持"
	case 0x08:
		return "地址类型不支持"
	default:
		return "未知错误 " + strconv.Itoa(int(code))
	}
}

// dialProxy 建立到代理的连接。https 代理走 TLS，并校验证书。
func dialProxy(host string, useTLS bool) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: dialTimeout}
	if !useTLS {
		return dialer.Dial("tcp", host)
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", host, &tls.Config{MinVersion: tls.VersionTLS12})
	if err != nil {
		return nil, fmt.Errorf("建立到 https 代理的 TLS 连接 %s: %w", host, err)
	}
	return conn, nil
}

// bufferedConn 让 bufio 预读的字节不丢失。
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}
