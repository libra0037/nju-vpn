package dial

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"testing"
)

// fakeSocks5 起一个只说"成功"的假 SOCKS5 代理，把请求里的地址部分记下来。
func fakeSocks5(t *testing.T) (addr string, got chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	got = make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)

		// 认证方法协商：版本 + 方法数 + 方法列表。
		head := make([]byte, 2)
		if _, err := io.ReadFull(br, head); err != nil {
			return
		}
		methods := make([]byte, head[1])
		if _, err := io.ReadFull(br, methods); err != nil {
			return
		}
		if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
			return
		}

		// 请求：版本 + 命令 + 保留 + 地址类型，后面跟地址与端口。
		reqHead := make([]byte, 4)
		if _, err := io.ReadFull(br, reqHead); err != nil {
			return
		}
		var rest []byte
		var prefix []byte
		switch reqHead[3] {
		case 0x01:
			rest = make([]byte, 4+2)
		case 0x04:
			rest = make([]byte, 16+2)
		case 0x03:
			l := make([]byte, 1)
			if _, err := io.ReadFull(br, l); err != nil {
				return
			}
			prefix = l
			rest = make([]byte, int(l[0])+2)
		default:
			return
		}
		if _, err := io.ReadFull(br, rest); err != nil {
			return
		}
		got <- append(append(reqHead, prefix...), rest...)

		// 应答：成功 + 空闲的 IPv4 绑定地址。
		if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
			return
		}
		// 连接保持打开，调用方还要用它。
		<-make(chan struct{})
	}()
	return ln.Addr().String(), got
}

// 回归：IP 字面量要走地址类型 0x01/0x04，不能一律当域名（0x03）发。
//
// 把 IP 当域名交给代理解析，IPv6 场景下必然失败，IPv4 也白绕一圈解析。
func TestSocks5SendsIPv4LiteralAsAddress(t *testing.T) {
	addr, got := fakeSocks5(t)
	dialFn, err := New("socks5://" + addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dialFn("tcp", "202.119.32.69:443"); err != nil {
		t.Fatalf("建连失败: %v", err)
	}
	req := <-got
	if req[3] != 0x01 {
		t.Fatalf("地址类型 = 0x%02x，IP 字面量应为 0x01", req[3])
	}
	if net.IP(req[4:8]).String() != "202.119.32.69" {
		t.Errorf("地址 = %v", net.IP(req[4:8]))
	}
	if binary.BigEndian.Uint16(req[8:10]) != 443 {
		t.Errorf("端口 = %d", binary.BigEndian.Uint16(req[8:10]))
	}
}

// 域名仍然交给代理解析（本机可能解析不了校园域名）。
func TestSocks5SendsDomainAsDomain(t *testing.T) {
	addr, got := fakeSocks5(t)
	dialFn, err := New("socks5://" + addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dialFn("tcp", "vpn.example.edu:443"); err != nil {
		t.Fatalf("建连失败: %v", err)
	}
	req := <-got
	if req[3] != 0x03 {
		t.Fatalf("地址类型 = 0x%02x，域名应为 0x03", req[3])
	}
	if req[4] != byte(len("vpn.example.edu")) {
		t.Errorf("域名长度 = %d", req[4])
	}
	if string(req[5:5+int(req[4])]) != "vpn.example.edu" {
		t.Errorf("域名 = %q", req[5:])
	}
}

// 回归：代理 URL 少了主机名时必须报错，不能静默连本机（":80" 会被当成空主机）。
func TestProxyURLRequiresHost(t *testing.T) {
	for _, proxy := range []string{"http://", "socks5://", "http://:7897"} {
		if _, err := New(proxy); err == nil {
			t.Errorf("%q 缺少主机名，应当报错", proxy)
		}
	}
}
