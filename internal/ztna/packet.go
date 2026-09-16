package ztna

import (
	"encoding/binary"
	"fmt"
	"net"
)

// 隧道里流动的是裸 IPv4 包。这里只做解析：客户端发什么由承载层决定，
// 协议层需要的是给逐流鉴权用的五元组。

const (
	protoICMP = 1
	protoTCP  = 6
	protoUDP  = 17

	ipv4MinHeader = 20
)

// flowKey 是一个方向的五元组标识。
type flowKey struct {
	atype uint8
	proto uint8
	src   string
	sport uint16
	dst   string
	dport uint16
}

func (k flowKey) String() string {
	return fmt.Sprintf("%d:%d:%s:%d-%s:%d", k.atype, k.proto, k.src, k.sport, k.dst, k.dport)
}

// packetInfo 是从 IP 包里取出来的信息。
type packetInfo struct {
	key     flowKey
	srcIP   net.IP
	dstIP   net.IP
	srcPort uint16
	dstPort uint16
	proto   uint8
}

// parsePacket 解析一个 IPv4 包并取出五元组。
// 任何越界或缺失都在这里被挡住，返回 ProtocolError 而不是 panic。
func parsePacket(pkt []byte) (packetInfo, error) {
	var info packetInfo
	if len(pkt) < ipv4MinHeader {
		return info, &ProtocolError{What: "IP 包过短", Got: fmt.Sprintf("%d 字节", len(pkt))}
	}
	if pkt[0]>>4 != 4 {
		return info, &ProtocolError{What: "不是 IPv4 包", Got: fmt.Sprintf("version=%d", pkt[0]>>4)}
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < ipv4MinHeader || len(pkt) < ihl {
		return info, &ProtocolError{What: "IPv4 头长度非法", Got: fmt.Sprintf("ihl=%d", ihl)}
	}
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if total > len(pkt) {
		return info, &ProtocolError{What: "IPv4 总长超过实际长度", Got: fmt.Sprintf("%d>%d", total, len(pkt))}
	}
	info.proto = pkt[9]
	info.srcIP = net.IP(pkt[12:16])
	info.dstIP = net.IP(pkt[16:20])

	switch info.proto {
	case protoTCP:
		if len(pkt) < ihl+20 {
			return info, &ProtocolError{What: "TCP 头不完整"}
		}
		info.srcPort = binary.BigEndian.Uint16(pkt[ihl : ihl+2])
		info.dstPort = binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
	case protoUDP:
		if len(pkt) < ihl+8 {
			return info, &ProtocolError{What: "UDP 头不完整"}
		}
		info.srcPort = binary.BigEndian.Uint16(pkt[ihl : ihl+2])
		info.dstPort = binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
	case protoICMP:
		// ICMP 没有端口，五元组里留 0。
	default:
		return info, &ProtocolError{What: "不支持的协议", Got: fmt.Sprintf("%d", info.proto)}
	}

	info.key = flowKey{
		atype: 4, proto: info.proto,
		src: info.srcIP.String(), sport: info.srcPort,
		dst: info.dstIP.String(), dport: info.dstPort,
	}
	return info, nil
}

// protoName 返回鉴权请求里用的协议名。
func protoName(proto uint8) string {
	switch proto {
	case protoTCP:
		return "tcp"
	case protoUDP:
		return "udp"
	case protoICMP:
		return "icmp"
	default:
		return "ip"
	}
}
