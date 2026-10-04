// Package l3 是隧道与承载层之间的唯一接缝：一条能收发裸 IP 包的通道。
//
// 它单独成包是为了让承载层（internal/wireguard）不必认识任何协议细节，
// 协议层也不必知道承载层长什么样——两边只依赖这一个类型。
package l3

import (
	"errors"
	"net"
	"sync/atomic"
)

// ErrNoUplink 表示上行通道尚未建立。
var ErrNoUplink = errors.New("隧道上行通道尚未建立")

// 每次注册有独立身份；注销只能移除自己注册的回调。
type uplinkBinding struct{ call func([]byte) error }
type downlinkBinding struct{ call func([]byte) }

type binding struct {
	uplink   *uplinkBinding
	downlink *downlinkBinding
}

// Endpoint 是隧道与承载之间的桥。
//
// 回调会被隧道协程与承载协程并发读写，这里用原子替换而不是互斥锁，
// 原因很具体：上行回调是往长连接写数据，可能被对端背压挡住很久，
// 持锁调用就等于要求"注销回调"也必须等它写完，早期实现因此能在
// 断开时永久卡住（命令不返回、登出发不出去）。原子替换的代价是允许
// 一瞬间的重叠：注销之后可能还有一个包落到旧回调上，它会拿到写错误
// 并被丢掉，不影响正确性。
type Endpoint struct {
	binding atomic.Pointer[binding]

	// local 是当前隧道地址（IPv4）。服务端会在会话中途下发地址
	// （0x96 的载荷是地址列表），承载层按它改写地址，所以这里只是
	// “最新值是多少”，不参与回调的原子替换。
	local atomic.Pointer[[4]byte]
}

// New 构造一个端点。
func New() *Endpoint { return &Endpoint{} }

// SetLocalAddr 记录当前隧道地址。非 IPv4（或 nil）会被忽略：承载层只改写
// IPv4，收到 IPv6 地址时保留原来的。
func (ep *Endpoint) SetLocalAddr(ip net.IP) {
	v4 := ip.To4()
	if v4 == nil {
		return
	}
	var addr [4]byte
	copy(addr[:], v4)
	ep.local.Store(&addr)
}

// LocalAddr 返回当前隧道地址；还没定下来时返回 nil。
func (ep *Endpoint) LocalAddr() net.IP {
	addr := ep.local.Load()
	if addr == nil {
		return nil
	}
	out := make(net.IP, net.IPv4len)
	copy(out, addr[:])
	return out
}

// LocalAddr4 返回当前隧道地址的 4 字节形式。
//
// 第二个返回值为 false 表示还没有地址。它不分配：承载层的地址映射每个包
// 都要读一次，而 LocalAddr 会 make 一个切片。
func (ep *Endpoint) LocalAddr4() ([4]byte, bool) {
	addr := ep.local.Load()
	if addr == nil {
		return [4]byte{}, false
	}
	return *addr, true
}

func (ep *Endpoint) update(change func(*binding)) {
	for {
		cur := ep.binding.Load()
		next := binding{}
		if cur != nil {
			next = *cur
		}
		change(&next)
		if ep.binding.CompareAndSwap(cur, &next) {
			return
		}
	}
}

// SetUplink 注册上行回调：把来自承载侧的裸 IP 包写进隧道。
func (ep *Endpoint) SetUplink(f func([]byte) error) func() {
	owner := &uplinkBinding{call: f}
	ep.update(func(b *binding) { b.uplink = owner })
	return func() {
		ep.update(func(b *binding) {
			if b.uplink == owner {
				b.uplink = nil
			}
		})
	}
}

// SetDownlink 注册下行回调：把隧道收到的裸 IP 包交给承载侧。
func (ep *Endpoint) SetDownlink(f func([]byte)) func() {
	owner := &downlinkBinding{call: f}
	ep.update(func(b *binding) { b.downlink = owner })
	return func() {
		ep.update(func(b *binding) {
			if b.downlink == owner {
				b.downlink = nil
			}
		})
	}
}

// Send 把上行的裸 IP 包交给隧道。不在锁里调用回调，理由见类型注释。
func (ep *Endpoint) Send(buf []byte) error {
	b := ep.binding.Load()
	if b == nil || b.uplink == nil {
		return ErrNoUplink
	}
	return b.uplink.call(buf)
}

// Deliver 把隧道下行的裸 IP 包交给承载侧。
func (ep *Endpoint) Deliver(buf []byte) {
	b := ep.binding.Load()
	if b == nil || b.downlink == nil {
		return
	}
	b.downlink.call(buf)
}
