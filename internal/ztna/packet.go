package ztna

import (
	"encoding/binary"
	"net"
)

const (
	protoICMP     = 1
	protoTCP      = 6
	protoUDP      = 17
	ipv4MinHeader = 20
)

type flowKey struct {
	atype uint8
	proto uint8
	src   [4]byte
	sport uint16
	dst   [4]byte
	dport uint16
}

func (k flowKey) srcString() string { return net.IP(k.src[:]).String() }
func (k flowKey) dstString() string { return net.IP(k.dst[:]).String() }

// Identification 只在同一源、目的、协议内有意义。
type fragmentKey struct {
	src, dst [4]byte
	proto    uint8
	id       uint16
}
type packetInfo struct {
	key              flowKey
	srcIP, dstIP     net.IP
	srcPort, dstPort uint16
	proto            uint8
	fragment         fragmentKey
	offset           uint32
	payloadBytes     uint32
	more             bool
}

func (p packetInfo) fragmented() bool { return p.more || p.offset != 0 }

// 尾片仅解析 IP 头，不把载荷开头当成端口。分片限制为无选项的 TCP/UDP，
// 且首片必须包含完整传输头；普通 IPv4 包仍可携带选项。
func parsePacket(pkt []byte) (packetInfo, error) {
	var p packetInfo
	reject := func(what string) (packetInfo, error) { return p, &ProtocolError{What: what} }
	if len(pkt) < ipv4MinHeader || pkt[0]>>4 != 4 {
		return reject("IP 包不是完整 IPv4 头")
	}
	ihl := int(pkt[0]&15) * 4
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	flags := binary.BigEndian.Uint16(pkt[6:8])
	p.offset = uint32(flags&0x1fff) * 8
	p.more = flags&0x2000 != 0
	p.proto = pkt[9]
	p.srcIP, p.dstIP = net.IP(pkt[12:16]), net.IP(pkt[16:20])
	p.key = flowKey{atype: 4, proto: p.proto}
	copy(p.key.src[:], pkt[12:16])
	copy(p.key.dst[:], pkt[16:20])
	p.fragment = fragmentKey{src: p.key.src, dst: p.key.dst, proto: p.proto, id: binary.BigEndian.Uint16(pkt[4:6])}
	if ihl < 20 || total != len(pkt) || total < ihl {
		return reject("IPv4 长度非法")
	}
	p.payloadBytes = uint32(total - ihl)
	if flags&0x8000 != 0 {
		return reject("IPv4 保留标志非零")
	}
	if p.fragmented() {
		if ihl != 20 || flags&0x4000 != 0 || p.payloadBytes == 0 ||
			p.more && p.payloadBytes%8 != 0 || p.offset+p.payloadBytes > 65535-20 ||
			p.proto != protoTCP && p.proto != protoUDP {
			return reject("IPv4 分片布局不受支持")
		}
		if p.offset != 0 {
			return p, nil
		}
	}
	payload := pkt[ihl:]
	switch p.proto {
	case protoTCP:
		if len(payload) < 20 {
			return reject("TCP 头不完整")
		}
		head := int(payload[12]>>4) * 4
		if head < 20 || head > len(payload) {
			return reject("TCP 头长度非法")
		}
	case protoUDP:
		if len(payload) < 8 {
			return reject("UDP 头不完整")
		}
		n := int(binary.BigEndian.Uint16(payload[4:6]))
		if n < 8 || !p.more && n != len(payload) || p.more && n < len(payload) {
			return reject("UDP 长度非法")
		}
	case protoICMP:
		if len(payload) < 8 {
			return reject("ICMP 头不完整")
		}
		return p, nil
	default:
		return reject("不支持的 IP 协议")
	}
	p.srcPort = binary.BigEndian.Uint16(payload[:2])
	p.dstPort = binary.BigEndian.Uint16(payload[2:4])
	p.key.sport, p.key.dport = p.srcPort, p.dstPort
	return p, nil
}
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
