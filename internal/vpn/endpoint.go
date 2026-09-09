package vpn

// TunnelEndpoint 是 L3 隧道和上层承载之间的桥。
//
// 旧仓库里它实现 gvisor 的 stack.LinkEndpoint 接口，包要经过一个完整的
// 用户态 TCP/IP 栈；现在服务端只做 L3 中继，网络栈挪到了客户端，所以这里
// 退化成两个回调，不再依赖 gvisor。
//
// 两个方向的语义沿用旧仓库，以免改动 tunnel.go：
//
//	OnRecv  由承载侧设置。隧道上行时调用，把裸 IP 包写进 TLS 长连接。
//	WriteTo 由 tunnel.go 调用。隧道下行收到包时触发 OnDeliver。
type TunnelEndpoint struct {
	// OnRecv 接收来自承载侧（WireGuard）的裸 IP 包，交由隧道发往校园网。
	OnRecv func(buf []byte)

	// OnDeliver 接收来自隧道的裸 IP 包，交由承载侧（WireGuard）发回客户端。
	OnDeliver func(buf []byte)
}

// WriteTo 把隧道下行收到的包交给承载侧。
func (ep *TunnelEndpoint) WriteTo(buf []byte) {
	if ep.OnDeliver != nil {
		ep.OnDeliver(buf)
	}
}
