package vpn

import (
	"errors"
	"sync"
)

// ErrNoUplink 表示隧道上行通道还没有建立。
var ErrNoUplink = errors.New("隧道上行通道尚未建立")

// TunnelEndpoint 是 L3 隧道和上层承载之间的桥。
//
// 两个方向都是回调，但回调字段会被隧道协程和承载协程并发读写，
// 所以必须走内部锁——旧实现把字段直接暴露出去，读取方和写入方之间
// 没有任何同步，真机跑起来就是数据竞争。
type TunnelEndpoint struct {
	mu       sync.RWMutex
	uplink   func([]byte) error
	downlink func([]byte)
}

// NewEndpoint 构造一个隧道端点。
func NewEndpoint() *TunnelEndpoint { return &TunnelEndpoint{} }

// SetUplink 注册上行回调：把来自承载侧的裸 IP 包写进隧道。
func (ep *TunnelEndpoint) SetUplink(f func([]byte) error) {
	ep.mu.Lock()
	ep.uplink = f
	ep.mu.Unlock()
}

// ClearUplink 注销上行回调。
func (ep *TunnelEndpoint) ClearUplink() {
	ep.mu.Lock()
	ep.uplink = nil
	ep.mu.Unlock()
}

// HasUplink 报告上行通道是否就绪。
func (ep *TunnelEndpoint) HasUplink() bool {
	ep.mu.RLock()
	defer ep.mu.RUnlock()
	return ep.uplink != nil
}

// Send 把上行的裸 IP 包交给隧道。
//
// 持读锁调用回调：回调内部是往长连接写数据，可能阻塞，
// 这样能保证 ClearUplink 返回后不会再有写入发生。
func (ep *TunnelEndpoint) Send(buf []byte) error {
	ep.mu.RLock()
	defer ep.mu.RUnlock()
	if ep.uplink == nil {
		return ErrNoUplink
	}
	return ep.uplink(buf)
}

// SetDownlink 注册下行回调：把隧道收到的裸 IP 包交给承载侧。
func (ep *TunnelEndpoint) SetDownlink(f func([]byte)) {
	ep.mu.Lock()
	ep.downlink = f
	ep.mu.Unlock()
}

// Deliver 把隧道下行的裸 IP 包交给承载侧。
func (ep *TunnelEndpoint) Deliver(buf []byte) {
	ep.mu.RLock()
	defer ep.mu.RUnlock()
	if ep.downlink != nil {
		ep.downlink(buf)
	}
}
