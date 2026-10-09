// Package packetlog 定义有限的丢包日志契约，供产品计数与发布测试采集共用。
// 展示文字、稳定原因和允许的来源只有一处；解析结果不携带原文或外部错误。
package packetlog

import (
	"fmt"
	"regexp"
	"strconv"
)

type Kind string

const (
	RelayDrop       Kind = "relay_drop"
	TunnelRejection Kind = "tunnel_reject"
)

type Reason string

const (
	DownlinkInvalid   Reason = "downlink_invalid"
	DownlinkAddress   Reason = "downlink_address"
	DownlinkFull      Reason = "downlink_full"
	DownlinkNoSession Reason = "downlink_no_session"
	UplinkInvalid     Reason = "uplink_invalid"
	UplinkAddress     Reason = "uplink_address"
	PeerNotReady      Reason = "peer_not_ready"
	ReadBufferFull    Reason = "read_buffer_full"
	UplinkNoSession   Reason = "uplink_no_session"
	UplinkUnavailable Reason = "uplink_unavailable"
	UplinkRejected    Reason = "uplink_rejected"
	StaleQueue        Reason = "stale_queue"
	MTUExceeded       Reason = "mtu_exceeded"
	LinkUnavailable   Reason = "link_unavailable"
	ResourceUnmatched Reason = "resource_unmatched"
	FlowRejected      Reason = "flow_rejected"
	PendingFull       Reason = "pending_full"
	FlowTableFull     Reason = "flow_table_full"
	FragmentMissing   Reason = "fragment_missing"
	FragmentOrder     Reason = "fragment_order"
	FragmentFull      Reason = "fragment_full"
	InvalidPacket     Reason = "invalid_packet"
)

func (k Kind) prefix() string {
	switch k {
	case RelayDrop:
		return "wireguard: 丢弃 "
	case TunnelRejection:
		return "上行拒绝："
	default:
		return ""
	}
}

// 空来源仅用于两处都可能发生的 MTU 拒绝；空文案表示未知类别。
func description(r Reason) (Kind, string) {
	switch r {
	case DownlinkInvalid:
		return RelayDrop, "下行数据切不出 IPv4 包"
	case DownlinkAddress:
		return RelayDrop, "下行包的目的地址不是本次分配到的地址（检查对端 allowed_ips 与 peer_address）"
	case DownlinkFull:
		return RelayDrop, "下行队列已满"
	case DownlinkNoSession:
		return RelayDrop, "会话已摘掉，下行包被丢弃（断开窗口里的尾巴）"
	case UplinkInvalid:
		return RelayDrop, "上行解出来的不是 IPv4 包"
	case UplinkAddress:
		return RelayDrop, "上行包的源地址不是 peer_address（对端 ip 配置不一致？）"
	case PeerNotReady:
		return RelayDrop, "对端尚未握手，下行包被丢弃（对端还没连上，或密钥不匹配）"
	case ReadBufferFull:
		return RelayDrop, "读缓冲装不下这个包"
	case UplinkNoSession:
		return RelayDrop, "隧道尚未建立，对端发来的包被丢弃"
	case UplinkUnavailable:
		return RelayDrop, "隧道上行通道未就绪，包被丢弃"
	case UplinkRejected:
		return RelayDrop, "隧道拒绝了这个上行包"
	case StaleQueue:
		return RelayDrop, "会话切换时丢掉了队列里属于旧会话的下行包（重连时正常）"
	case MTUExceeded:
		return "", "报文超过配置 MTU"
	case LinkUnavailable:
		return TunnelRejection, "链路或会话不可用"
	case ResourceUnmatched:
		return TunnelRejection, "资源表外"
	case FlowRejected:
		return TunnelRejection, "流鉴权失败"
	case PendingFull:
		return TunnelRejection, "待鉴权缓存已满"
	case FlowTableFull:
		return TunnelRejection, "流表已满"
	case FragmentMissing:
		return TunnelRejection, "分片关联不存在或过期"
	case FragmentOrder:
		return TunnelRejection, "分片乱序或重叠"
	case FragmentFull:
		return TunnelRejection, "分片关联已满"
	case InvalidPacket:
		return TunnelRejection, "报文格式非法"
	default:
		return "", ""
	}
}

// Format 的参数由内部有限计数类别给出；非法组合是编程错误。
func Format(kind Kind, reason Reason, count uint64) string {
	owner, label := description(reason)
	prefix := kind.prefix()
	if prefix == "" || label == "" || owner != "" && owner != kind {
		panic("非法丢包日志类别")
	}
	return fmt.Sprintf("%s%s（reason=%s，累计 %d 个包）", prefix, label, reason, count)
}

type Event struct {
	Kind   Kind
	Reason Reason
	Count  uint64
}

var pattern = regexp.MustCompile(`^(wireguard: 丢弃 |上行拒绝：)(.+)（reason=([a-z_]+)，累计 ([0-9]+) 个包）$`)

// Parse 不解析日期；输入只允许有限类别的完整日志正文，上限 512 字节。
func Parse(message string) (Event, bool) {
	if len(message) > 512 {
		return Event{}, false
	}
	parts := pattern.FindStringSubmatch(message)
	if parts == nil {
		return Event{}, false
	}
	kind := RelayDrop
	if parts[1] != kind.prefix() {
		kind = TunnelRejection
	}
	reason := Reason(parts[3])
	owner, label := description(reason)
	if label == "" || label != parts[2] || owner != "" && owner != kind {
		return Event{}, false
	}
	count, err := strconv.ParseUint(parts[4], 10, 64)
	if err != nil {
		return Event{}, false
	}
	return Event{Kind: kind, Reason: reason, Count: count}, true
}
