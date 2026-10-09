package packetlog

import (
	"fmt"
	"strings"
	"testing"
)

func TestCurrentPacketLogContractHasIndependentFixtures(t *testing.T) {
	for _, tc := range []struct {
		kind, prefix, reason, label string
	}{
		{"relay_drop", "wireguard: 丢弃 ", "downlink_invalid", "下行数据切不出 IPv4 包"},
		{"relay_drop", "wireguard: 丢弃 ", "downlink_address", "下行包的目的地址不是本次分配到的地址（检查对端 allowed_ips 与 peer_address）"},
		{"relay_drop", "wireguard: 丢弃 ", "downlink_full", "下行队列已满"},
		{"relay_drop", "wireguard: 丢弃 ", "downlink_no_session", "会话已摘掉，下行包被丢弃（断开窗口里的尾巴）"},
		{"relay_drop", "wireguard: 丢弃 ", "uplink_invalid", "上行解出来的不是 IPv4 包"},
		{"relay_drop", "wireguard: 丢弃 ", "uplink_address", "上行包的源地址不是 peer_address（对端 ip 配置不一致？）"},
		{"relay_drop", "wireguard: 丢弃 ", "peer_not_ready", "对端尚未握手，下行包被丢弃（对端还没连上，或密钥不匹配）"},
		{"relay_drop", "wireguard: 丢弃 ", "read_buffer_full", "读缓冲装不下这个包"},
		{"relay_drop", "wireguard: 丢弃 ", "uplink_no_session", "隧道尚未建立，对端发来的包被丢弃"},
		{"relay_drop", "wireguard: 丢弃 ", "uplink_unavailable", "隧道上行通道未就绪，包被丢弃"},
		{"relay_drop", "wireguard: 丢弃 ", "uplink_rejected", "隧道拒绝了这个上行包"},
		{"relay_drop", "wireguard: 丢弃 ", "stale_queue", "会话切换时丢掉了队列里属于旧会话的下行包（重连时正常）"},
		{"relay_drop", "wireguard: 丢弃 ", "mtu_exceeded", "报文超过配置 MTU"},
		{"tunnel_reject", "上行拒绝：", "link_unavailable", "链路或会话不可用"},
		{"tunnel_reject", "上行拒绝：", "resource_unmatched", "资源表外"},
		{"tunnel_reject", "上行拒绝：", "flow_rejected", "流鉴权失败"},
		{"tunnel_reject", "上行拒绝：", "pending_full", "待鉴权缓存已满"},
		{"tunnel_reject", "上行拒绝：", "flow_table_full", "流表已满"},
		{"tunnel_reject", "上行拒绝：", "fragment_missing", "分片关联不存在或过期"},
		{"tunnel_reject", "上行拒绝：", "fragment_order", "分片乱序或重叠"},
		{"tunnel_reject", "上行拒绝：", "fragment_full", "分片关联已满"},
		{"tunnel_reject", "上行拒绝：", "mtu_exceeded", "报文超过配置 MTU"},
		{"tunnel_reject", "上行拒绝：", "invalid_packet", "报文格式非法"},
	} {
		t.Run(tc.kind+"/"+tc.reason, func(t *testing.T) {
			// 独立文案与固定布局；不把 Format 输出作为 Parse 的输入判据。
			wire := tc.prefix + tc.label + "（reason=" + tc.reason + "，累计 7 个包）"
			if got := Format(Kind(tc.kind), Reason(tc.reason), 7); got != wire {
				t.Fatal("丢包日志布局改变", got)
			}
			got, ok := Parse(wire)
			if !ok || string(got.Kind) != tc.kind || string(got.Reason) != tc.reason || got.Count != 7 {
				t.Fatal("当前有限分类被遗漏", got, ok)
			}
		})
	}
}

func TestPacketLogRejectsUnknownOldAndInvalidMessages(t *testing.T) {
	for _, message := range []string{
		"wireguard: 丢弃 下行队列已满（累计 1 个）",
		"上行拒绝：报文格式或容量超限，累计 1 个包",
		"上行拒绝：报文格式或容量超限（reason=packet_capacity，累计 1 个包）",
		"wireguard: 丢弃 secret-token（reason=mtu_exceeded，累计 1 个包）",
		"wireguard: 丢弃 分片关联已满（reason=fragment_full，累计 1 个包）",
		"上行拒绝：下行队列已满（reason=downlink_full，累计 1 个包）",
		"上行拒绝：报文格式非法（reason=unknown，累计 1 个包）",
		"上行拒绝：报文格式非法（reason=invalid_packet，累计 18446744073709551616 个包）",
		"上行拒绝：报文格式非法（reason=invalid_packet，累计 -1 个包）",
		"上行拒绝：报文格式非法（reason=invalid_packet，累计 1 个包） trailing-secret",
		strings.Repeat("x", 513),
	} {
		if event, ok := Parse(message); ok || event != (Event{}) {
			t.Fatal("非法原文进入日志摘要", event, ok)
		}
	}
	for _, tc := range []struct {
		kind   Kind
		reason Reason
	}{{"invalid", MTUExceeded}, {RelayDrop, FragmentFull}, {TunnelRejection, DownlinkFull}, {RelayDrop, "invalid"}} {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("内部非法日志分类未触发守卫")
				}
			}()
			Format(tc.kind, tc.reason, 1)
		})
	}
}
