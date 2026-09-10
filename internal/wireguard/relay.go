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
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"njuvpn/internal/vpn"
)

// ErrClosed 表示 relay 已经关闭。
var ErrClosed = errors.New("wireguard relay 已关闭")

const (
	// queueSize 是隧道下行方向的缓冲包数。WireGuard 读得慢时多出来的包会被丢弃，
	// 这对承载 TCP 是可接受的：丢包会触发重传，而阻塞读取会拖慢整条隧道。
	queueSize = 128

	// maxFrameBuffer 限制分帧缓冲区的上限。接不上包的垃圾字节不应该
	// 让服务进程的内存一直涨。
	maxFrameBuffer = 64 * 1024

	// dropLogInterval 是丢包日志的最小间隔。
	dropLogInterval = 5 * time.Second
)

// RelayOptions 是构造 Relay 的参数。
type RelayOptions struct {
	// MTU 是暴露给 WireGuard 的 MTU。
	MTU int
	// Endpoint 是隧道端点。
	Endpoint *vpn.TunnelEndpoint
	// Mapper 在 peer 地址与校园网分配地址之间改写 IP 包，可为 nil。
	Mapper *Mapper
}

// Relay 实现 tun.Device，把 WireGuard 和校园网隧道对接起来。
type Relay struct {
	mtu    int
	ep     *vpn.TunnelEndpoint
	mapper *Mapper
	queue  chan []byte

	events    chan tun.Event
	closed    chan struct{}
	closeOnce sync.Once

	// 上行是字节流，需要按 IPv4 总长度重新切包。
	frameMu  sync.Mutex
	frameBuf []byte

	dropped    atomic.Uint64
	lastDropAt atomic.Int64
}

// NewRelay 创建 relay，并把两个方向接到 endpoint 上。
func NewRelay(opts RelayOptions) *Relay {
	mtu := opts.MTU
	if mtu <= 0 {
		mtu = 1320
	}
	r := &Relay{
		mtu:    mtu,
		ep:     opts.Endpoint,
		mapper: opts.Mapper,
		queue:  make(chan []byte, queueSize),
		events: make(chan tun.Event, 8),
		closed: make(chan struct{}),
	}

	opts.Endpoint.SetDownlink(r.deliver)

	// 设备已经就绪，直接报告 Up。这里没有真正的网卡需要等待系统拉起。
	r.events <- tun.EventUp

	return r
}

// deliver 接收隧道下行的字节流，按 IP 总长度切包后放进队列。
//
// 调用方（隧道读循环）复用读缓冲，所以这里必须拷贝；
// 而且不能假设"一次读 = 一个包"——粘包与半包都会出现。
func (r *Relay) deliver(chunk []byte) {
	select {
	case <-r.closed:
		return
	default:
	}

	r.frameMu.Lock()
	r.frameBuf = append(r.frameBuf, chunk...)
	var packets [][]byte
	for {
		pkt, rest, err := splitPacket(r.frameBuf)
		if err != nil {
			// 对端给了不符合 IPv4 的字节，丢掉整段缓冲等下一个包同步。
			log.Printf("wireguard: 下行数据无法解析为 IPv4 包: %v", err)
			r.frameBuf = nil
			break
		}
		if pkt == nil {
			break
		}
		packets = append(packets, pkt)
		r.frameBuf = rest
	}
	if len(r.frameBuf) > maxFrameBuffer {
		log.Printf("wireguard: 下行分帧缓冲超过 %d 字节，丢弃", maxFrameBuffer)
		r.frameBuf = nil
	}
	r.frameMu.Unlock()

	for _, pkt := range packets {
		if r.mapper != nil {
			rewritten, err := r.mapper.Downlink(pkt)
			if err != nil {
				r.countDrop()
				continue
			}
			pkt = rewritten
		}
		select {
		case r.queue <- pkt:
		case <-r.closed:
			return
		default:
			// 队列满，丢弃。隧道里的 TCP 会重传，UDP 本来就允许丢。
			r.countDrop()
		}
	}
}

// splitPacket 从缓冲里切出一个完整 IP 包。
//
// 返回 (nil, buf, nil) 表示数据还不够一个包，需要继续等。
func splitPacket(buf []byte) (pkt []byte, rest []byte, err error) {
	if len(buf) < ipv4MinHeader {
		return nil, buf, nil
	}
	total, err := ipv4TotalLength(buf)
	if err != nil {
		return nil, nil, err
	}
	if total > maxFrameBuffer {
		return nil, nil, fmt.Errorf("IPv4 总长度 %d 超出上限", total)
	}
	if len(buf) < total {
		return nil, buf, nil
	}
	pkt = make([]byte, total)
	copy(pkt, buf[:total])
	return pkt, buf[total:], nil
}

// countDrop 记录丢包并按间隔限速打日志。
func (r *Relay) countDrop() {
	n := r.dropped.Add(1)
	now := time.Now().UnixNano()
	last := r.lastDropAt.Load()
	if now-last < int64(dropLogInterval) || !r.lastDropAt.CompareAndSwap(last, now) {
		return
	}
	log.Printf("wireguard: 下行队列已满或包不合法，累计丢弃 %d 个包", n)
}

// File 返回 nil：这里没有操作系统层面的网卡文件描述符。
func (r *Relay) File() *os.File { return nil }

// Read 取一个来自校园网的包交给 WireGuard 加密后发往客户端。
func (r *Relay) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}
	// 先查关闭状态：否则 Close 之后队列里剩的包还会被交出去。
	select {
	case <-r.closed:
		return 0, ErrClosed
	default:
	}

	for {
		select {
		case pkt := <-r.queue:
			dst := bufs[0][offset:]
			if len(pkt) > len(dst) {
				// 装不下就丢掉这个包，绝不能返回错误：wireguard-go 的 TUN 读
				// 协程收到非 ErrClosed 的错误会直接 go device.Close()，一个
				// 超长包就能把整条承载层悄悄关掉（Windows 上缓冲区只有 2000
				// 字节，而隧道侧允许更大的包）。丢包由上层重传兜住。
				r.countDrop()
				continue
			}
			sizes[0] = copy(dst, pkt)
			return 1, nil
		case <-r.closed:
			return 0, ErrClosed
		}
	}
}

// Write 把 WireGuard 解出来的客户端包送进校园网隧道。
func (r *Relay) Write(bufs [][]byte, offset int) (int, error) {
	select {
	case <-r.closed:
		return 0, ErrClosed
	default:
	}
	if !r.ep.HasUplink() {
		return 0, vpn.ErrNoUplink
	}

	n := 0
	for _, buf := range bufs {
		pkt := buf[offset:]
		if len(pkt) == 0 {
			continue
		}
		if _, err := parseIPv4(pkt); err != nil {
			// WireGuard 解出来的应该是 IPv4 包，其它一律丢弃。
			r.countDrop()
			continue
		}
		if r.mapper != nil {
			rewritten, err := r.mapper.Uplink(pkt)
			if err != nil {
				r.countDrop()
				continue
			}
			pkt = rewritten
		}
		if err := r.ep.Send(pkt); err != nil {
			return n, err
		}
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

// Close 停止设备并关闭事件通道。可安全重复调用。
func (r *Relay) Close() error {
	r.closeOnce.Do(func() {
		if r.ep != nil {
			r.ep.SetDownlink(nil)
		}
		close(r.closed)
		r.events <- tun.EventDown
		close(r.events)
	})
	return nil
}

var _ tun.Device = (*Relay)(nil)
