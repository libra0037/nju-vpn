package wireguard

// Diagnostics 的计数属于承载设备，停止校园会话后仍保留，到进程退出为止。
// Configured 指设备当前已装载对端；Ready 指已握手或收到解密数据，不保证业务可达。
type Diagnostics struct {
	Configured bool              `json:"configured"`
	Ready      bool              `json:"ready"`
	Drops      map[string]uint64 `json:"drops"`
}

// 固定诊断键不使用业务地址；与有限原因计数一一对应。
var dropReasonName = [dropReasonCount]string{
	dropDownlinkInvalid:   "downlink_invalid",
	dropDownlinkAddr:      "downlink_address",
	dropDownlinkFull:      "downlink_full",
	dropDownlinkNoSession: "downlink_no_session",
	dropUplinkNotIPv4:     "uplink_invalid",
	dropUplinkAddr:        "uplink_address",
	dropPeerNotReady:      "peer_not_ready",
	dropNoBuffer:          "read_buffer_full",
	dropNoSession:         "uplink_no_session",
	dropNoUplink:          "uplink_unavailable",
	dropUplinkRejected:    "uplink_rejected",
	dropStaleQueue:        "stale_queue",
	dropMTUExceeded:       "mtu_exceeded",
}
