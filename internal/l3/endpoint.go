// Package l3 是隧道与承载层之间的唯一接缝：一条能收发裸 IP 包的通道。
//
// 它单独成包是为了让承载层（internal/wireguard）不必认识任何协议细节，
// 协议层也不必知道承载层长什么样——两边只依赖这一个类型。
package l3

import (
	"errors"
	"sync/atomic"
)

// ErrNoUplink 表示上行通道尚未建立。
var ErrNoUplink = errors.New("隧道上行通道尚未建立")

// binding 是一次会话注册在端点上的两个回调，整体被原子替换：
// 改方向时不会出现"上行换了新会话、下行还指着旧的"这种中间状态，
// 读写双方也不需要任何锁。
type binding struct {
	uplink   func([]byte) error
	downlink func([]byte)
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
}

// New 构造一个端点。
func New() *Endpoint { return &Endpoint{} }

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
func (ep *Endpoint) SetUplink(f func([]byte) error) {
	ep.update(func(b *binding) { b.uplink = f })
}

// ClearUplink 注销上行回调，立即返回，不等正在进行的写入结束。
func (ep *Endpoint) ClearUplink() {
	ep.update(func(b *binding) { b.uplink = nil })
}

// SetDownlink 注册下行回调：把隧道收到的裸 IP 包交给承载侧。
func (ep *Endpoint) SetDownlink(f func([]byte)) {
	ep.update(func(b *binding) { b.downlink = f })
}

// ClearDownlink 注销下行回调。
func (ep *Endpoint) ClearDownlink() {
	ep.update(func(b *binding) { b.downlink = nil })
}

// HasUplink 报告上行通道是否就绪。
func (ep *Endpoint) HasUplink() bool {
	b := ep.binding.Load()
	return b != nil && b.uplink != nil
}

// Send 把上行的裸 IP 包交给隧道。不在锁里调用回调，理由见类型注释。
func (ep *Endpoint) Send(buf []byte) error {
	b := ep.binding.Load()
	if b == nil || b.uplink == nil {
		return ErrNoUplink
	}
	return b.uplink(buf)
}

// Deliver 把隧道下行的裸 IP 包交给承载侧。
func (ep *Endpoint) Deliver(buf []byte) {
	b := ep.binding.Load()
	if b == nil || b.downlink == nil {
		return
	}
	b.downlink(buf)
}
