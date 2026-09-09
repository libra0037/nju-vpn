package wireguard

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// Mapper 在两类地址之间改写 IP 包的源/目的地址：
//
//	上行  客户端 peer 的固定地址 → 校园网分配的隧道地址（改源）
//	下行  校园网分配的隧道地址   → 客户端 peer 的固定地址（改目的）
//
// 改写后必须修正校验和。这里用 RFC 1624 的增量算法，而不是整包重算：
// 分片报文的非首片没有传输层头部，整包重算无从下手，增量更新则只需知道
// 变了哪两个 16 位字。
type Mapper struct {
	peerIP   [4]byte // 客户端 peer 的地址，例如 10.66.66.2
	publicIP [4]byte // 隧道分配的地址，例如 172.29.56.18
}

// NewMapper 构造地址映射。两个地址都必须是 IPv4。
func NewMapper(peer, public net.IP) (*Mapper, error) {
	p4, err := to4(peer)
	if err != nil {
		return nil, fmt.Errorf("peer 地址: %w", err)
	}
	q4, err := to4(public)
	if err != nil {
		return nil, fmt.Errorf("隧道地址: %w", err)
	}
	return &Mapper{peerIP: p4, publicIP: q4}, nil
}

func to4(ip net.IP) ([4]byte, error) {
	var out [4]byte
	v4 := ip.To4()
	if v4 == nil {
		return out, fmt.Errorf("不是 IPv4 地址: %v", ip)
	}
	copy(out[:], v4)
	return out, nil
}

// Uplink 把客户端发出的包改写为隧道地址发出，原地修改 buf。
func (m *Mapper) Uplink(buf []byte) ([]byte, error) {
	hdr, err := parseIPv4(buf)
	if err != nil {
		return nil, err
	}
	if !equal4(buf[ipv4SrcOffset:], m.peerIP) {
		return nil, fmt.Errorf("上行包源地址不是 peer 地址 %s", net.IP(m.peerIP[:]))
	}
	m.rewriteAddr(buf, hdr, ipv4SrcOffset, m.peerIP, m.publicIP)
	return buf, nil
}

// Downlink 把隧道收到的包改写为发往客户端，原地修改 buf。
func (m *Mapper) Downlink(buf []byte) ([]byte, error) {
	hdr, err := parseIPv4(buf)
	if err != nil {
		return nil, err
	}
	if !equal4(buf[ipv4DstOffset:], m.publicIP) {
		return nil, fmt.Errorf("下行包目的地址不是隧道地址 %s", net.IP(m.publicIP[:]))
	}
	m.rewriteAddr(buf, hdr, ipv4DstOffset, m.publicIP, m.peerIP)
	return buf, nil
}

// rewriteAddr 改掉 at 处的 4 字节地址，并同步修正 IP 头与传输层校验和。
func (m *Mapper) rewriteAddr(buf []byte, hdr ipv4Header, at int, old, new [4]byte) {
	copy(buf[at:], new[:])

	// IP 头校验和：两个 16 位字各变了一次。
	csum := binary.BigEndian.Uint16(buf[ipv4ChecksumOff:])
	csum = updateChecksum(csum, binary.BigEndian.Uint16(old[0:2]), binary.BigEndian.Uint16(new[0:2]))
	csum = updateChecksum(csum, binary.BigEndian.Uint16(old[2:4]), binary.BigEndian.Uint16(new[2:4]))
	binary.BigEndian.PutUint16(buf[ipv4ChecksumOff:], csum)

	// 分片的非首片没有传输层头部，到此为止。
	if hdr.fragmentOffset() != 0 {
		return
	}

	switch hdr.protocol {
	case protocolTCP:
		off := hdr.headerLen + tcpChecksumOff
		if len(buf) < off+2 {
			return
		}
		c := binary.BigEndian.Uint16(buf[off:])
		c = updateChecksum(c, binary.BigEndian.Uint16(old[0:2]), binary.BigEndian.Uint16(new[0:2]))
		c = updateChecksum(c, binary.BigEndian.Uint16(old[2:4]), binary.BigEndian.Uint16(new[2:4]))
		binary.BigEndian.PutUint16(buf[off:], c)

	case protocolUDP:
		off := hdr.headerLen + udpChecksumOff
		if len(buf) < off+2 {
			return
		}
		c := binary.BigEndian.Uint16(buf[off:])
		// UDP 校验和为 0 表示发送端没算校验和，此时不能动它。
		if c == udpChecksumZero {
			return
		}
		c = updateChecksum(c, binary.BigEndian.Uint16(old[0:2]), binary.BigEndian.Uint16(new[0:2]))
		c = updateChecksum(c, binary.BigEndian.Uint16(old[2:4]), binary.BigEndian.Uint16(new[2:4]))
		binary.BigEndian.PutUint16(buf[off:], c)
	}
}

type ipv4Header struct {
	headerLen int
	protocol  byte
	fragField uint16
}

func (h ipv4Header) fragmentOffset() int { return int(h.fragField & fragmentMask) }

const (
	ipv4MinHeader   = 20
	ipv4SrcOffset   = 12
	ipv4DstOffset   = 16
	ipv4ChecksumOff = 10
	fragmentFieldAt = 6
	fragmentMask    = 0x1fff
	protocolTCP     = 6
	protocolUDP     = 17
	tcpChecksumOff  = 16
	udpChecksumOff  = 6
	udpChecksumZero = 0
)

func parseIPv4(buf []byte) (ipv4Header, error) {
	if len(buf) < ipv4MinHeader {
		return ipv4Header{}, errors.New("包太短，不是 IPv4 报文")
	}
	if buf[0]>>4 != 4 {
		return ipv4Header{}, fmt.Errorf("不是 IPv4 报文（版本 %d）", buf[0]>>4)
	}
	headLen := int(buf[0]&0x0f) * 4
	if headLen < ipv4MinHeader || len(buf) < headLen {
		return ipv4Header{}, fmt.Errorf("IPv4 头部长度非法: %d", headLen)
	}
	return ipv4Header{
		headerLen: headLen,
		protocol:  buf[9],
		fragField: binary.BigEndian.Uint16(buf[fragmentFieldAt:]),
	}, nil
}

func equal4(b []byte, want [4]byte) bool {
	return len(b) >= 4 && b[0] == want[0] && b[1] == want[1] && b[2] == want[2] && b[3] == want[3]
}

// updateChecksum 用 RFC 1624 公式更新一个校验和：
//
//	HC' = ~(~HC + ~m + m')
func updateChecksum(checksum, old, new uint16) uint16 {
	sum := uint32(^checksum&0xffff) + uint32(^old&0xffff) + uint32(new)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
