package vpn

import (
	"errors"
	"sync/atomic"
)

// ErrNoUplink 表示隧道上行通道还没有建立。
var ErrNoUplink = errors.New("隧道上行通道尚未建立")

// endpointBinding 是一次会话注册在端点上的两个回调。
//
// 它整体被原子替换：改方向时不会出现"上行换了新会话、下行还指着旧的"
// 这种中间状态，读写双方也不需要任何锁。
type endpointBinding struct {
	uplink   func([]byte) error
	downlink func([]byte)
}

// TunnelEndpoint 是 L3 隧道和上层承载之间的桥。
//
// 两个方向都是回调，而回调字段会被隧道协程与承载协程并发读写。这里用
// 原子替换而不是互斥锁，原因很具体：回调是往长连接写数据，可能阻塞很久，
// 持锁调用就等于要求"注销回调"也必须等它写完。旧实现正是这样卡死的——
// 上行写被对端背压挡住时，Run 的收尾（ClearUplink）与 dev.Close()
// （它要 SetDownlink(nil)）会一起永久挂住，连登出都发不出去。
//
// 原子替换的代价是允许一瞬间的重叠：注销之后可能还有一个包落到旧回调上。
// 那个包会拿到 EOF 之类的写错误并被丢掉，不影响正确性。
type TunnelEndpoint struct {
	binding atomic.Pointer[endpointBinding]
}

// NewEndpoint 构造一个隧道端点。
func NewEndpoint() *TunnelEndpoint { return &TunnelEndpoint{} }

// update 原子地改一份 binding 拷贝。
func (ep *TunnelEndpoint) update(change func(*endpointBinding)) {
	for {
		cur := ep.binding.Load()
		next := endpointBinding{}
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
func (ep *TunnelEndpoint) SetUplink(f func([]byte) error) {
	ep.update(func(b *endpointBinding) { b.uplink = f })
}

// ClearUplink 注销上行回调。立即返回，不等正在进行的写入结束。
func (ep *TunnelEndpoint) ClearUplink() {
	ep.update(func(b *endpointBinding) { b.uplink = nil })
}

// SetDownlink 注册下行回调：把隧道收到的裸 IP 包交给承载侧。
func (ep *TunnelEndpoint) SetDownlink(f func([]byte)) {
	ep.update(func(b *endpointBinding) { b.downlink = f })
}

// ClearDownlink 注销下行回调。
func (ep *TunnelEndpoint) ClearDownlink() {
	ep.update(func(b *endpointBinding) { b.downlink = nil })
}

// HasUplink 报告上行通道是否就绪。
func (ep *TunnelEndpoint) HasUplink() bool {
	b := ep.binding.Load()
	return b != nil && b.uplink != nil
}

// Send 把上行的裸 IP 包交给隧道。
//
// 不在锁里调用回调：写长连接可能阻塞，而注销必须能立刻返回。
func (ep *TunnelEndpoint) Send(buf []byte) error {
	b := ep.binding.Load()
	if b == nil || b.uplink == nil {
		return ErrNoUplink
	}
	return b.uplink(buf)
}

// Deliver 把隧道下行的裸 IP 包交给承载侧。
func (ep *TunnelEndpoint) Deliver(buf []byte) {
	b := ep.binding.Load()
	if b == nil || b.downlink == nil {
		return
	}
	b.downlink(buf)
}
