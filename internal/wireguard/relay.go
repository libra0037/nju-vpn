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
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/libra0037/nju-vpn/internal/vpn"
)

// ErrClosed 表示 relay 已经关闭。
var ErrClosed = errors.New("wireguard relay 已关闭")

const (
	// queueSize 是隧道下行方向的缓冲包数。WireGuard 读得慢时多出来的包会被丢弃，
	// 这对承载 TCP 是可接受的：丢包会触发重传，而阻塞读取会拖慢整条隧道。
	queueSize = 128

	// dropLogInterval 是丢包日志的最小间隔。
	dropLogInterval = 5 * time.Second
)

// RelayOptions 是构造 Relay 的参数。
type RelayOptions struct {
	// MTU 是暴露给 WireGuard 的 MTU。
	MTU int
}

// relaySession 是一次校园网会话在承载层里的接线。
//
// 设备活到进程结束，而会话每次 start 都是新的：服务端分配的校园网地址
// 不同，Mapper 就得跟着换一份。整个结构体原子替换，两个方向都不会看到
// "上行已换新、下行还指着旧会话"这种中间状态。
type relaySession struct {
	ep     *vpn.TunnelEndpoint
	mapper *Mapper
}

// Relay 实现 tun.Device，把 WireGuard 和校园网隧道对接起来。
type Relay struct {
	mtu   int
	queue chan []byte

	// session 为 nil 表示当前没有校园网会话：客户端发来的包直接丢弃。
	session atomic.Pointer[relaySession]

	events    chan tun.Event
	closed    chan struct{}
	closeOnce sync.Once

	// 上行是字节流，需要按 IPv4 总长度重新切包。
	frameMu  sync.Mutex
	frameBuf []byte

	// 丢包按原因分开计数：混成一个数字时，"隧道 up 却一个包都过不去"
	// 这种最常见的问题在日志里没有任何线索。
	drops [dropReasonCount]dropCounter
}

// NewRelay 创建 relay。
//
// 建的时候没有会话：设备可以先起来监听，等隧道通了再用 InstallSession
// 接上。这样"端口被占""私钥写错"这类问题在进程启动时就暴露，不必等到
// 登录、短信、建隧道全部走完。
func NewRelay(opts RelayOptions) *Relay {
	mtu := opts.MTU
	if mtu <= 0 {
		mtu = 1320
	}
	r := &Relay{
		mtu:    mtu,
		queue:  make(chan []byte, queueSize),
		events: make(chan tun.Event, 8),
		closed: make(chan struct{}),
	}

	// 设备已经就绪，直接报告 Up。这里没有真正的网卡需要等待系统拉起。
	r.events <- tun.EventUp

	return r
}

// InstallSession 把承载层接到一次校园网会话上。
//
// 可以反复调用。换绑之后旧会话的回调立刻失效；旧会话残留的下行包即使
// 挤进来，也会因为目的地址不等于新会话分配到的地址而被 Mapper 丢掉。
func (r *Relay) InstallSession(ep *vpn.TunnelEndpoint, mapper *Mapper) {
	r.session.Store(&relaySession{ep: ep, mapper: mapper})
	ep.SetDownlink(r.deliver)
}

// ClearSession 摘掉当前会话。设备继续监听，但不再有任何包进出隧道。
func (r *Relay) ClearSession() {
	if old := r.session.Swap(nil); old != nil {
		old.ep.ClearDownlink()
	}
}

// deliver 接收隧道下行的字节流，按 IP 总长度切包后放进队列。
//
// 调用方（隧道读循环）复用读缓冲，所以这里必须拷贝；
// 而且不能假设"一次读 = 一个包"——粘包与半包都会出现。
//
// 缓冲区不会无限涨：切不出包时会把整段丢弃等下一个包同步，
// 而单个包的长度受 IPv4 总长度（16 位）限制。
func (r *Relay) deliver(chunk []byte) {
	select {
	case <-r.closed:
		return
	default:
	}
	sess := r.session.Load()
	if sess == nil {
		// 会话刚被摘掉，这是最后一瞬间漂进来的包。
		return
	}

	r.frameMu.Lock()
	r.frameBuf = append(r.frameBuf, chunk...)
	var packets [][]byte
	for {
		pkt, rest, err := splitPacket(r.frameBuf)
		if err != nil {
			// 对端给了不符合 IPv4 的字节，丢掉整段缓冲等下一个包同步。
			// 走统一的计数与限速：以前这里是裸日志，下行一旦失步就按
			// chunk 刷屏，而 DropStats 里一条记录都没有。
			r.countDrop(dropDownlinkInvalid)
			r.frameBuf = nil
			break
		}
		if pkt == nil {
			break
		}
		packets = append(packets, pkt)
		r.frameBuf = rest
	}
	r.frameMu.Unlock()

	for _, pkt := range packets {
		if sess.mapper != nil {
			rewritten, err := sess.mapper.Downlink(pkt)
			if err != nil {
				r.countDrop(dropDownlinkAddr)
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
			r.countDrop(dropDownlinkFull)
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
	if len(buf) < total {
		return nil, buf, nil
	}
	pkt = make([]byte, total)
	copy(pkt, buf[:total])
	return pkt, buf[total:], nil
}

// dropReason 是丢包原因。每种原因单独计数、单独限速打日志。
type dropReason int

const (
	// dropDownlinkInvalid：隧道下行来的字节切不出 IPv4 包。
	dropDownlinkInvalid dropReason = iota
	// dropDownlinkAddr：下行包的目的地址不是本次分配到的校园网地址。
	// 客户端 allowed_ips 写错、或 connect 时分配了新地址时会出现。
	dropDownlinkAddr
	// dropDownlinkFull：下行队列满（WireGuard 读得慢）。
	dropDownlinkFull
	// dropUplinkNotIPv4：WireGuard 解出来的不是 IPv4 包。
	dropUplinkNotIPv4
	// dropUplinkAddr：上行包的源地址不是 peer 地址——最典型的成因是
	// 客户端配置里的 ip 与 wireguard.peer_address 不一致。
	dropUplinkAddr
	// dropNoBuffer：读缓冲装不下这个包（见 Read 的注释）。
	dropNoBuffer
	// dropNoSession：客户端发来的包到达时还没有校园网会话（隧道没建、
	// 或正在断开），整批丢弃。
	dropNoSession
	// dropNoUplink：有会话但上行通道还没接上（Run 正在建流，或刚被摘掉）。
	dropNoUplink

	dropReasonCount
)

var dropReasonText = [dropReasonCount]string{
	dropDownlinkInvalid: "下行数据切不出 IPv4 包",
	dropDownlinkAddr:    "下行包的目的地址不是本次分配到的地址（检查客户端 allowed_ips 与 peer_address）",
	dropDownlinkFull:    "下行队列已满",
	dropUplinkNotIPv4:   "上行解出来的不是 IPv4 包",
	dropUplinkAddr:      "上行包的源地址不是 peer_address（客户端 ip 配置不一致？）",
	dropNoBuffer:        "读缓冲装不下这个包",
	dropNoSession:       "隧道尚未建立，客户端发来的包被丢弃",
	dropNoUplink:        "隧道上行通道未就绪，包被丢弃",
}

// dropCounter 是一种原因的计数与限速状态。
type dropCounter struct {
	n        atomic.Uint64
	lastLog  atomic.Int64
	firstLog atomic.Bool
}

// countDrop 记录一次丢包，并按原因限速打日志。
//
// 每种原因第一次出现必定打一条（否则用户第一次踩配置错误时什么都没看到），
// 之后按间隔限速。
func (r *Relay) countDrop(reason dropReason) {
	c := &r.drops[reason]
	n := c.n.Add(1)
	if c.firstLog.CompareAndSwap(false, true) {
		c.lastLog.Store(time.Now().UnixNano())
		log.Printf("wireguard: 丢弃 %s（累计 %d 个）", dropReasonText[reason], n)
		return
	}
	now := time.Now().UnixNano()
	last := c.lastLog.Load()
	if now-last < int64(dropLogInterval) || !c.lastLog.CompareAndSwap(last, now) {
		return
	}
	log.Printf("wireguard: 丢弃 %s（累计 %d 个）", dropReasonText[reason], n)
}

// DropStats 返回每种原因的累计丢包数，供测试与排查使用。
func (r *Relay) DropStats() map[string]uint64 {
	out := make(map[string]uint64, dropReasonCount)
	for reason := dropReason(0); reason < dropReasonCount; reason++ {
		if n := r.drops[reason].n.Load(); n > 0 {
			out[dropReasonText[reason]] = n
		}
	}
	return out
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
				r.countDrop(dropNoBuffer)
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
	sess := r.session.Load()
	if sess == nil {
		// 没有会话时静默丢弃，而不是回一个错误：wireguard-go 的接收协程
		// 见到 Write 报错会按包打一行 Error 级日志（receive.go 的
		// "Failed to write packets to TUN device"），断线窗口里客户端
		// 每个包都能刷出一行。丢包本身由上层重传兜住，日志由计数限速接管。
		r.countDrop(dropNoSession)
		return len(bufs), nil
	}

	n := 0
	for _, buf := range bufs {
		pkt := buf[offset:]
		if len(pkt) == 0 {
			continue
		}
		if _, err := parseIPv4(pkt); err != nil {
			// WireGuard 解出来的应该是 IPv4 包，其它一律丢弃。
			r.countDrop(dropUplinkNotIPv4)
			continue
		}
		if sess.mapper != nil {
			rewritten, err := sess.mapper.Uplink(pkt)
			if err != nil {
				r.countDrop(dropUplinkAddr)
				continue
			}
			pkt = rewritten
		}
		if err := sess.ep.Send(pkt); err != nil {
			// 上行还没注册（Run 正在建流）或刚被摘掉：同样静默丢弃，
			// 理由同上——回错误只会换来一行按包的 Error 日志。
			r.countDrop(dropNoUplink)
			continue
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
		// 先摘会话：之后隧道侧不会再往这个设备里投包。
		r.ClearSession()
		close(r.closed)
		r.events <- tun.EventDown
		close(r.events)
	})
	return nil
}

var _ tun.Device = (*Relay)(nil)
