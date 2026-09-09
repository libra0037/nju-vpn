// Package wireguard 把 WireGuard 用户态实现接到校园网隧道上。
//
// 这里不创建 TUN 网卡：本进程是服务端，客户端（sing-box / Clash 之类）
// 自带用户态网络栈。WireGuard 的 tun.Device 接口被实现成一个内存管道，
// 两端分别是 WireGuard 的数据平面和校园网隧道。
//
// 方向对照：
//
//	WireGuard Read  → 从隧道取包（校园网回给客户端）
//	WireGuard Write → 把包送进隧道（客户端发往校园网）
package wireguard

import (
	"errors"
	"log"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"

	"njuvpn/internal/vpn"
)

// ErrClosed 表示 relay 已经关闭。
var ErrClosed = errors.New("wireguard relay 已关闭")

// queueSize 是隧道下行方向的缓冲包数。WireGuard 读得慢时多出来的包会被丢弃，
// 这对承载 TCP 是可接受的：丢包会触发重传，而阻塞读取会拖慢整条隧道。
const queueSize = 128

// Relay 实现 tun.Device，把 WireGuard 和校园网隧道对接起来。
type Relay struct {
	mtu   int
	ep    *vpn.TunnelEndpoint
	queue chan []byte

	events    chan tun.Event
	closed    chan struct{}
	closeOnce sync.Once
}

// NewRelay 创建 relay，并把两个方向接到 endpoint 上。
//
// endpoint.OnDeliver 由隧道层调用，把下行包投递给 WireGuard；
// endpoint.OnRecv 由本包调用，把上行包写进隧道。
func NewRelay(mtu int, ep *vpn.TunnelEndpoint) *Relay {
	if mtu <= 0 {
		mtu = 1320
	}
	r := &Relay{
		mtu:    mtu,
		ep:     ep,
		queue:  make(chan []byte, queueSize),
		events: make(chan tun.Event, 8),
		closed: make(chan struct{}),
	}

	ep.OnDeliver = r.deliver

	// 设备已经就绪，直接报告 Up。这里没有真正的网卡需要等待系统拉起。
	r.events <- tun.EventUp

	return r
}

// deliver 把隧道下行的裸 IP 包放进队列，等 WireGuard 来读。
// 调用方复用读缓冲，所以这里必须拷贝。
func (r *Relay) deliver(buf []byte) {
	pkt := make([]byte, len(buf))
	copy(pkt, buf)

	select {
	case r.queue <- pkt:
	case <-r.closed:
	default:
		// 队列满，丢弃。隧道里的 TCP 会重传，UDP 本来就允许丢。
		log.Printf("wireguard: 下行队列已满，丢弃 %d 字节", len(pkt))
	}
}

// File 返回 nil：这里没有操作系统层面的网卡文件描述符。
func (r *Relay) File() *os.File { return nil }

// Read 取一个来自校园网的包交给 WireGuard 加密后发往客户端。
func (r *Relay) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}
	select {
	case pkt := <-r.queue:
		n := copy(bufs[0][offset:], pkt)
		sizes[0] = n
		return 1, nil
	case <-r.closed:
		return 0, ErrClosed
	}
}

// Write 把 WireGuard 解出来的客户端包送进校园网隧道。
func (r *Relay) Write(bufs [][]byte, offset int) (int, error) {
	if r.ep.OnRecv == nil {
		return 0, errors.New("隧道上行通道尚未建立")
	}

	n := 0
	for _, buf := range bufs {
		pkt := buf[offset:]
		if len(pkt) == 0 {
			continue
		}
		r.ep.OnRecv(pkt)
		n++
	}
	return n, nil
}

// MTU 返回设备 MTU。
func (r *Relay) MTU() (int, error) { return r.mtu, nil }

// Name 返回设备名，仅用于日志。
func (r *Relay) Name() (string, error) { return "njuvpn", nil }

// Events 返回设备事件通道。
func (r *Relay) Events() <-chan tun.Event { return r.events }

// BatchSize 返回单次读写的包数上限。单 peer 场景下不需要批量。
func (r *Relay) BatchSize() int { return 1 }

// Close 停止设备并关闭事件通道。
func (r *Relay) Close() error {
	r.closeOnce.Do(func() {
		close(r.closed)
		r.events <- tun.EventDown
		close(r.events)
	})
	return nil
}

var _ tun.Device = (*Relay)(nil)
