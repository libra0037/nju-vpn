// Package wireguard 把 WireGuard 用户态实现接到校园网隧道上。
//
// 这里不创建 TUN 网卡：本进程是承载层，对端（sing-box / Clash 之类）
// 自带用户态网络栈。WireGuard 的 tun.Device 接口被实现成一个内存管道，
// 两端分别是 WireGuard 的数据平面和校园网隧道。
//
// 方向对照：
//
//	WireGuard Read  → 从隧道取包（校园网回给对端）
//	WireGuard Write → 把包送进隧道（对端发往校园网）
package wireguard

import (
	"errors"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/libra0037/nju-vpn/internal/l3"
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
	ep         *l3.Endpoint
	mapper     *Mapper
	unregister func()
}

type queuedPacket struct {
	owner *relaySession
	data  []byte
}

// Relay 实现 tun.Device，把 WireGuard 和校园网隧道对接起来。
type Relay struct {
	mtu    int
	queue  chan queuedPacket
	bindMu sync.Mutex

	// session 为 nil 表示当前没有校园网会话：对端发来的包直接丢弃。
	session atomic.Pointer[relaySession]

	// hold 与 peerSeen 一起决定下行方向要不要把包交给 WireGuard。
	//
	// 配好了 peer、对端还没露面时，设备不知道它在哪儿：包交上去也发不
	// 出去，只会换来 wireguard-go 每 5 秒一行 ERROR "no known endpoint for
	// peer"（真机上隧道建好后的 57 秒里刷了 12 行）。而这段窗口可以很长——
	// 校园网网关自己就会往分配到的地址发包。
	//
	// hold 跟着 peer 一起开关（见 Device.SetPeer / ClearPeer），peerSeen 是
	// "对端确实接进来了"的证据：收到它解出来的第一个数据包时置位。之所以
	// 不问设备要 "peer 的地址"：Read 跑在 wireguard-go 的 TUN 读取协程里，
	// 在那里调 IpcGet 会和它的状态机抢 ipcMutex，实测能把设备锁死（Close
	// 永远等不到读取协程退出）。
	hold     atomic.Bool
	peerSeen atomic.Bool

	// holdWake 在每次装/摘 peer 时响一下，给 watchPeerHandshake 一个即时信号。
	// 没有它，探测循环只能靠轮询发现"会话刚接上"，而那段空转要么费电要么
	// 让下行闩锁慢几秒才松开。
	holdWake chan struct{}

	events    chan tun.Event
	closed    chan struct{}
	closeOnce sync.Once

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
	r := &Relay{
		mtu:      opts.MTU,
		queue:    make(chan queuedPacket, queueSize),
		events:   make(chan tun.Event, 8),
		closed:   make(chan struct{}),
		holdWake: make(chan struct{}, 1),
	}

	// 设备已经就绪，直接报告 Up。这里没有真正的网卡需要等待系统拉起。
	r.events <- tun.EventUp

	return r
}

// InstallSession 把承载层接到一次校园网会话上。
//
// 可以反复调用。换绑之后旧会话的回调立刻失效；队列里属于旧会话的下行包
// 一并排空（它们的地址是按旧会话改写好的，交出去就是一批孤儿包）。
//
// 回调的输入约定：投递的必须是**完整**的 IPv4 包，不是字节流。生产路径上
// 唯一的调用方是隧道读循环，它先用 splitPackets 切好边界再逐包投递。切包
// 缓冲因此不存在——它防的是永远不会到达的半包，而且让"读者要记得它还留着
// 半截字节"变成一个跨会话的状态。
func (r *Relay) InstallSession(ep *l3.Endpoint, mapper *Mapper) {
	r.bindMu.Lock()
	defer r.bindMu.Unlock()
	if old := r.session.Swap(nil); old != nil {
		old.unregister()
	}
	r.dropStaleQueue()
	sess := &relaySession{ep: ep, mapper: mapper}
	sess.unregister = ep.SetDownlink(func(pkt []byte) { r.deliverFrom(sess, pkt) })
	select {
	case <-r.closed:
		sess.unregister()
		return
	default:
	}
	r.session.Store(sess)
}

// HoldDownlink 开关下行方向的等待：hold 为真表示设备里配好了 peer、对端
// 随时会连进来，在它露面之前下行包先扣下（丢掉并计数，见 Read）。
//
// 打开时会一并忘掉"对端露过面"：换 key（SetPeer）之后新对端必须重新
// 握手，下行方向才会再次放行。关掉时（ClearPeer 之后设备里根本没有 peer）
// 包照旧交给 WireGuard，它会因为找不到目的 peer 而静默丢弃。
func (r *Relay) HoldDownlink(hold bool) {
	r.peerSeen.Store(false)
	r.hold.Store(hold)
	select {
	case r.holdWake <- struct{}{}:
	default:
	}
}

// ClearSession 摘掉当前会话。设备继续监听，但不再有任何包进出隧道。
func (r *Relay) ClearSession() {
	r.bindMu.Lock()
	defer r.bindMu.Unlock()
	if old := r.session.Swap(nil); old != nil {
		old.unregister()
	}
	r.dropStaleQueue()
}

// dropStaleQueue 丢掉队列里属于上一个会话的下行包。
//
// 队列里存的是已经按旧会话地址改写好的包：换绑之后新会话的映射认不出它们
// （下行包的目的地址对不上），交给对端就是一批孤儿包，而且不会有任何
// 记录。会话换绑是唯一知道"这些包已经没用了"的时刻。
func (r *Relay) dropStaleQueue() {
	for {
		select {
		case <-r.queue:
			r.countDrop(dropStaleQueue)
		default:
			return
		}
	}
}

// deliver 接收隧道下行的一个完整 IPv4 包，改写地址后放进队列。
//
// 输入约定见 InstallSession：调用方投递的是完整包。这里只做一次边界校验
// （长度必须正好等于 IPv4 头里声明的总长度）：不满足就整段丢掉并计数——
// 宁可丢一个包，也不能把错位的字节当成包交给 WireGuard。
//
// 调用方（隧道读循环）复用读缓冲，切出来的包是同一块内存的视图，所以入队
// 前必须拷贝。
func (r *Relay) deliverFrom(sess *relaySession, pkt []byte) {
	select {
	case <-r.closed:
		return
	default:
	}
	if sess != r.session.Load() {
		// 会话刚被摘掉，这是最后一瞬间漂进来的包。
		r.countDrop(dropDownlinkNoSession)
		return
	}

	total, err := ipv4TotalLength(pkt)
	if err != nil || total != len(pkt) || total > r.mtu {
		r.countDrop(dropDownlinkInvalid)
		return
	}
	out := make([]byte, len(pkt))
	copy(out, pkt)
	if sess.mapper != nil {
		rewritten, err := sess.mapper.Downlink(out)
		if err != nil {
			r.countDrop(dropDownlinkAddr)
			return
		}
		out = rewritten
	}
	// 映射可与解绑交错；检查与入队在同一交接锁内，不能在排空后再入旧包。
	r.bindMu.Lock()
	if sess != r.session.Load() {
		r.bindMu.Unlock()
		r.countDrop(dropStaleQueue)
		return
	}
	full := false
	select {
	case r.queue <- queuedPacket{owner: sess, data: out}:
	case <-r.closed:
	default:
		full = true
	}
	r.bindMu.Unlock()
	if full {
		r.countDrop(dropDownlinkFull)
	}
}

// dropReason 是丢包原因。每种原因单独计数、单独限速打日志。
type dropReason int

const (
	// dropDownlinkInvalid：隧道下行来的字节切不出 IPv4 包。
	dropDownlinkInvalid dropReason = iota
	// dropDownlinkAddr：下行包的目的地址不是本次分配到的校园网地址。
	// 对端 allowed_ips 写错、或 connect 时分配了新地址时会出现。
	dropDownlinkAddr
	// dropDownlinkFull：下行队列满（WireGuard 读得慢）。
	dropDownlinkFull
	// dropDownlinkNoSession：隧道下行包到达时会话刚被摘掉（断开窗口里的
	// 尾巴）。以前这里静默返回，丢了多少没有任何线索。
	dropDownlinkNoSession
	// dropUplinkNotIPv4：WireGuard 解出来的不是 IPv4 包。
	dropUplinkNotIPv4
	// dropUplinkAddr：上行包的源地址不是 peer 地址——最典型的成因是
	// 对端配置里的 ip 与 wireguard.peer_address 不一致。
	dropUplinkAddr
	// dropPeerNotReady：下行包送到时设备还不知道对端在哪儿。整批丢掉，
	// 因为交给 wireguard-go 也发不出去——它只会每 5 秒往日志里写一行
	// "no known endpoint for peer"。
	dropPeerNotReady
	// dropNoBuffer：读缓冲装不下这个包（见 Read 的注释）。
	dropNoBuffer
	// dropNoSession：对端发来的包到达时还没有校园网会话（隧道没建、
	// 或正在断开），整批丢弃。
	dropNoSession
	// dropNoUplink：有会话但上行通道还没接上（Run 正在建流，或刚被摘掉）。
	dropNoUplink
	// dropUplinkRejected：上行通道接上了，但隧道拒绝了这个包
	//（最常见的是目标不在资源表内、或该流鉴权失败）。
	dropUplinkRejected
	// dropStaleQueue：会话切换（重连、换账号）时队列里还留着属于旧会话的
	// 下行包。它们的地址是按旧会话改写好的，交出去就是一批孤儿包。
	dropStaleQueue

	dropReasonCount
)

var dropReasonText = [dropReasonCount]string{
	dropDownlinkInvalid:   "下行数据切不出 IPv4 包",
	dropDownlinkAddr:      "下行包的目的地址不是本次分配到的地址（检查对端 allowed_ips 与 peer_address）",
	dropDownlinkFull:      "下行队列已满",
	dropDownlinkNoSession: "会话已摘掉，下行包被丢弃（断开窗口里的尾巴）",
	dropUplinkNotIPv4:     "上行解出来的不是 IPv4 包",
	dropUplinkAddr:        "上行包的源地址不是 peer_address（对端 ip 配置不一致？）",
	dropPeerNotReady:      "对端尚未握手，下行包被丢弃（对端还没连上，或密钥不匹配）",
	dropNoBuffer:          "读缓冲装不下这个包",
	dropNoSession:         "隧道尚未建立，对端发来的包被丢弃",
	dropNoUplink:          "隧道上行通道未就绪，包被丢弃",
	dropUplinkRejected:    "隧道拒绝了这个上行包",
	dropStaleQueue:        "会话切换时丢掉了队列里属于旧会话的下行包（重连时正常）",
}

// dropQuietInterval 是几种"预期之内、会一直重复"的丢包原因的日志间隔。
//
// 典型的是对端还没露面：校园网网关自己就会往分配到的地址发包，隧道刚
// 建好、对端还没连上时这段窗口可以很长。这类丢包第一次打一条足够用户
// 知道发生了什么，之后按这个间隔报一次数，不必跟着默认间隔刷屏。
// 零值表示用默认的 dropLogInterval。
var dropQuietInterval = [dropReasonCount]time.Duration{
	dropPeerNotReady:      5 * time.Minute,
	dropDownlinkNoSession: 5 * time.Minute,
	dropStaleQueue:        5 * time.Minute,
}

// dropCounter 是一种原因的计数与限速状态。
type dropCounter struct {
	n       atomic.Uint64
	lastLog atomic.Int64
}

// countDrop 记录一次丢包，并按原因限速打日志。
//
// 每种原因第一次出现必定打一条（否则用户第一次踩配置错误时什么都没看到），
// 之后按间隔限速；原因文案变了则立刻再打一条。
func (r *Relay) countDrop(reason dropReason) { r.countDropDetail(reason, nil) }

// countDropDetail 与 countDrop 同样限速，但把具体原因一起打出来。
//
// 上行被拒的理由只有调用点知道（目标不在资源表内、该流鉴权失败……），
// 混进一句固定文案就等于把排查推回"猜"：实测时日志只说"上行通道未就绪"，
// 而真实原因是资源表的端口范围把 ICMP 挡在了门外。
func (r *Relay) countDropDetail(reason dropReason, detail error) {
	c := &r.drops[reason]
	n := c.n.Add(1)
	text := dropReasonText[reason]
	// 外部错误可能含地址或令牌；日志只记录有限的本地原因类别。
	report := func() { log.Printf("wireguard: 丢弃 %s（累计 %d 个）", text, n) }
	interval := dropLogInterval
	if quiet := dropQuietInterval[reason]; quiet > 0 {
		interval = quiet
	}
	now := time.Now().UnixNano()
	last := c.lastLog.Load()
	if now-last < int64(interval) || !c.lastLog.CompareAndSwap(last, now) {
		return
	}
	report()
}

// File 返回 nil：这里没有操作系统层面的网卡文件描述符。
func (r *Relay) File() *os.File { return nil }

// Read 取一个来自校园网的包交给 WireGuard 加密后发往对端。
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
		case item := <-r.queue:
			if item.owner != r.session.Load() {
				r.countDrop(dropStaleQueue)
				continue
			}
			pkt := item.data
			if r.hold.Load() && !r.peerSeen.Load() {
				// 配了 peer、对端还没露面：设备不知道它在哪儿，交上去也发不
				// 出去，只会换来一行 "no known endpoint for peer"。
				r.countDrop(dropPeerNotReady)
				continue
			}
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

// Write 把 WireGuard 解出来的对端包送进校园网隧道。
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
		// "Failed to write packets to TUN device"），断线窗口里对端
		// 每个包都能刷出一行。丢包本身由上层重传兜住，日志由计数限速接管。
		r.countDrop(dropNoSession)
		return len(bufs), nil
	}

	// 走到这里说明对端的数据包已经解出来交给我们了：它握手成功、
	// 而且设备记住了它的地址，下行方向可以放行。
	r.peerSeen.Store(true)

	n := 0
	for _, buf := range bufs {
		if offset < 0 || offset > len(buf) {
			r.countDrop(dropUplinkNotIPv4)
			continue
		}
		pkt := buf[offset:]
		if len(pkt) == 0 {
			continue
		}
		if _, err := parseIPv4(pkt); err != nil || len(pkt) > r.mtu {
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
			// 上行还没注册（Run 正在建流）与"隧道明确拒绝了这个包"是两回事：
			// 前者是时序，后者要用户去查资源表或鉴权。两者都静默丢弃，理由
			// 同上——回错误只会换来一行按包的 Error 日志。
			if errors.Is(err, l3.ErrNoUplink) {
				r.countDrop(dropNoUplink)
			} else {
				r.countDropDetail(dropUplinkRejected, err)
			}
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
		close(r.closed)
		// 先摘会话：之后隧道侧不会再往这个设备里投包。
		r.ClearSession()
		r.events <- tun.EventDown
		close(r.events)
	})
	return nil
}

var _ tun.Device = (*Relay)(nil)
