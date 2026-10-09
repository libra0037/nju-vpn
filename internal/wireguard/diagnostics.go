package wireguard

import "github.com/libra0037/nju-vpn/internal/packetlog"

// Diagnostics 的计数属于承载设备，停止校园会话后仍保留，到进程退出为止。
// Configured 指设备当前已装载对端；Ready 指已握手或收到解密数据，不保证业务可达。
type Diagnostics struct {
	Configured bool              `json:"configured"`
	Ready      bool              `json:"ready"`
	Drops      map[string]uint64 `json:"drops"`
}

// 固定诊断键不使用业务地址；与有限原因计数一一对应。
var dropReasonName = [dropReasonCount]string{
	dropDownlinkInvalid:   string(packetlog.DownlinkInvalid),
	dropDownlinkAddr:      string(packetlog.DownlinkAddress),
	dropDownlinkFull:      string(packetlog.DownlinkFull),
	dropDownlinkNoSession: string(packetlog.DownlinkNoSession),
	dropUplinkNotIPv4:     string(packetlog.UplinkInvalid),
	dropUplinkAddr:        string(packetlog.UplinkAddress),
	dropPeerNotReady:      string(packetlog.PeerNotReady),
	dropNoBuffer:          string(packetlog.ReadBufferFull),
	dropNoSession:         string(packetlog.UplinkNoSession),
	dropNoUplink:          string(packetlog.UplinkUnavailable),
	dropUplinkRejected:    string(packetlog.UplinkRejected),
	dropStaleQueue:        string(packetlog.StaleQueue),
	dropMTUExceeded:       string(packetlog.MTUExceeded),
}
