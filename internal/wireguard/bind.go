package wireguard

import (
	"fmt"
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

// ListenHost 决定 UDP 绑定在哪个地址上。
type ListenHost int

const (
	// ListenLoopback 只绑定回环地址。服务端与客户端在同一台机器上时用这个：
	// 同一个局域网里的其他人连不上这个端口。
	ListenLoopback ListenHost = iota
	// ListenAll 绑定全部网卡，需要从其他机器接入时才用。
	ListenAll
)

// ParseListenHost 解析配置里的监听地址写法。
func ParseListenHost(s string) (ListenHost, error) {
	switch s {
	case "", "loopback", "local", "127.0.0.1":
		return ListenLoopback, nil
	case "all", "any", "0.0.0.0":
		return ListenAll, nil
	default:
		return ListenLoopback, fmt.Errorf("wireguard.listen_host 只能是 loopback 或 all，收到 %q", s)
	}
}

// newBind 按监听范围创建绑定。
func newBind(host ListenHost) conn.Bind {
	if host == ListenAll {
		return conn.NewDefaultBind()
	}
	return &loopbackBind{}
}

// loopbackBind 是只绑定回环地址的最小 conn.Bind 实现。
//
// wireguard-go 自带的绑定用的是 ":port"，也就是 0.0.0.0:port：同一个
// 局域网里任何人都能打到这个 UDP 端口。服务端与客户端同机时没有这个
// 必要，所以这里自己实现一份，只监听 127.0.0.1。
//
// 只做同机场景需要的事：批量大小固定为 1，不使用 GSO、PKTINFO 与
// SO_MARK。这些上游优化在回环上没有意义。
type loopbackBind struct {
	mu   sync.Mutex
	conn *net.UDPConn
}

// Open 在回环地址上打开指定端口，端口填 0 时由系统分配。
func (b *loopbackBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.conn != nil {
		// 端口变化时上游会重新 Open，先把旧的关掉。
		b.conn.Close()
		b.conn = nil
	}

	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)}
	udpConn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, 0, fmt.Errorf("监听 %s: %w", addr, err)
	}
	b.conn = udpConn

	actual := uint16(udpConn.LocalAddr().(*net.UDPAddr).Port)
	return []conn.ReceiveFunc{b.receive}, actual, nil
}

// receive 是接收函数：一次读一个包。
func (b *loopbackBind) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	b.mu.Lock()
	udpConn := b.conn
	b.mu.Unlock()
	if udpConn == nil {
		return 0, net.ErrClosed
	}

	n, addr, err := udpConn.ReadFromUDPAddrPort(packets[0])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	eps[0] = &conn.StdNetEndpoint{AddrPort: addr}
	return 1, nil
}

// Close 关闭监听。关闭后接收函数会返回 net.ErrClosed。
func (b *loopbackBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn == nil {
		return nil
	}
	err := b.conn.Close()
	b.conn = nil
	return err
}

// SetMark 在回环场景下不需要设置 SO_MARK。
func (b *loopbackBind) SetMark(uint32) error { return nil }

// Send 把数据报发给指定端点。
func (b *loopbackBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	sendTo, ok := ep.(*conn.StdNetEndpoint)
	if !ok {
		return fmt.Errorf("不支持的端点类型 %T", ep)
	}

	b.mu.Lock()
	udpConn := b.conn
	b.mu.Unlock()
	if udpConn == nil {
		return net.ErrClosed
	}

	addr := net.UDPAddrFromAddrPort(sendTo.AddrPort)
	for _, buf := range bufs {
		if len(buf) == 0 {
			continue
		}
		if _, err := udpConn.WriteToUDP(buf, addr); err != nil {
			return err
		}
	}
	return nil
}

// ParseEndpoint 解析 "地址:端口"。
func (b *loopbackBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	addrPort, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &conn.StdNetEndpoint{AddrPort: addrPort}, nil
}

// BatchSize 固定为 1：回环上不需要批量。
func (b *loopbackBind) BatchSize() int { return 1 }

var _ conn.Bind = (*loopbackBind)(nil)
