package wireguard

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"sync/atomic"
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
	peerIP [4]byte // 客户端 peer 的地址，例如 10.66.66.2
	// public 现取隧道分配的地址，例如 172.29.56.18。
	//
	// 用回调而不是固定值：服务端会在会话中途下发地址（0x96，载荷是地址
	// 列表），地址一变映射就得跟着走，否则下行每个包都因“目的地址不是隧道
	// 地址”被丢、上行被改写成旧源地址，表现是 up 却一个包都不通。
	public func() net.IP

	// 未支持的传输层协议只提示一次，避免每包都打日志。
	unsupportedLogged atomic.Bool
}

// NewDynamicMapper 与 NewMapper 一样，只是隧道地址由回调现取：地址在会话
// 中途变化时映射要跟着走，不能把构造时的值冻住。回调可能被上下行两个协程
// 并发调用，必须自己保证安全。
func NewDynamicMapper(peer net.IP, public func() net.IP) (*Mapper, error) {
	if public == nil {
		return nil, fmt.Errorf("隧道地址回调为空")
	}
	p4, err := to4(peer)
	if err != nil {
		return nil, fmt.Errorf("peer 地址: %w", err)
	}
	// 构造时先要一个值，配置写错要在启动时就暴露，而不是等第一个包。
	if _, err := to4(public()); err != nil {
		return nil, fmt.Errorf("隧道地址: %w", err)
	}
	return &Mapper{peerIP: p4, public: public}, nil
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
	public, err := m.currentPublic()
	if err != nil {
		return nil, err
	}
	m.rewriteAddr(buf, hdr, ipv4SrcOffset, m.peerIP, public)
	return buf, nil
}

// Downlink 把隧道收到的包改写为发往客户端，原地修改 buf。
func (m *Mapper) Downlink(buf []byte) ([]byte, error) {
	hdr, err := parseIPv4(buf)
	if err != nil {
		return nil, err
	}
	public, err := m.currentPublic()
	if err != nil {
		return nil, err
	}
	if !equal4(buf[ipv4DstOffset:], public) {
		return nil, fmt.Errorf("下行包目的地址不是隧道地址 %s", net.IP(public[:]))
	}
	m.rewriteAddr(buf, hdr, ipv4DstOffset, public, m.peerIP)
	return buf, nil
}

// currentPublic 取当前隧道地址。取不到时报错：调用方会按丢包计数，比拿一个
// 过期地址去改写安全得多。
func (m *Mapper) currentPublic() ([4]byte, error) {
	var out [4]byte
	ip := m.public()
	v4 := ip.To4()
	if v4 == nil {
		return out, fmt.Errorf("隧道地址不可用: %v", ip)
	}
	copy(out[:], v4)
	return out, nil
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
		// 算出来是 0 时线上写全 1（RFC 1071）：UDP 里 0x0000 的含义是
		// "发送端没算校验和"，接收端会跳过校验。
		if c == 0 {
			c = 0xffff
		}
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
		// RFC 768：算出来是 0 时线上要写全 1。写成 0x0000 会被接收端
		// 理解成"发送端没算校验和"，从而跳过校验。
		if c == 0 {
			c = 0xffff
		}
		binary.BigEndian.PutUint16(buf[off:], c)

	case protocolICMP:
		m.rewriteICMPInner(buf, hdr, old, new)

	default:
		// 还有别的协议把地址算进校验和（SCTP 132、DCCP 33、UDP-Lite 136）。
		// 不白名单化：ICMP 这类没有伪头校验和的协议会被误伤，而校园网里
		// 这些协议基本不会出现。真出现了至少留一条线索——校验和坏掉的
		// 表现是"包发出去了但没回应"，光看现象查不出来。
		if hasPseudoHeaderChecksum(hdr.protocol) && m.unsupportedLogged.CompareAndSwap(false, true) {
			log.Printf("wireguard: 改写了含地址的 %s 校验和未更新，该协议可能不通（只提示一次）",
				protocolName(hdr.protocol))
		}
	}
}

// icmpCarriesOriginal 报告这种 ICMP 类型是否把"触发差错的原始报文"附在消息里。
//
// 3 目的不可达、4 源抑制（已废弃）、5 重定向、11 超时、12 参数问题。
// 回显请求/应答（8/0）也带 4 字节"其余部分"，但那是标识与序号，不是报文。
func icmpCarriesOriginal(typ byte) bool {
	switch typ {
	case 3, 4, 5, 11, 12:
		return true
	}
	return false
}

// rewriteICMPInner 改写 ICMP 差错报文里内嵌的原始 IPv4 头。
//
// 差错报文把触发它的原始报文的前若干字节附在消息里，多数协议栈按内层的
// 四元组把差错关联回套接字：内层地址与它们发出的那个包对不上，差错就被
// 丢掉。路径 MTU 发现（需要分片那条也算在内）因此失效，大包路径黑掉，
// 表现是"发出去了没回应"。
//
// 内层头不完整（差错只带了一小段，或根本不是 IPv4）就原样放过：那种报文
// 解析不了，动了只会更糟。外层 ICMP 校验和覆盖整条消息，内层改完必须重算。
func (m *Mapper) rewriteICMPInner(buf []byte, hdr ipv4Header, old, new [4]byte) {
	// 非首片里没有 ICMP 头：这些字节是消息的中间部分，按 ICMP 头解析会
	// 把载荷当内嵌报文改。内嵌报文只出现在首片的开头。
	if hdr.fragmentOffset() != 0 {
		return
	}
	icmp := hdr.headerLen
	if len(buf) < icmp+icmpMinLen+ipv4MinHeader {
		return
	}
	if !icmpCarriesOriginal(buf[icmp]) {
		return
	}

	inner := icmp + icmpEmbeddedOff
	innerHdr, err := parseIPv4(buf[inner:])
	if err != nil {
		return
	}
	// 内层两个地址里最多有一个是我们的：上行方向它是源（客户端报的是它
	// 收到的包），下行方向它是目的。两个都查一遍就不必区分方向。
	var srcChanged, dstChanged bool
	if equal4(buf[inner+ipv4SrcOffset:], old) {
		copy(buf[inner+ipv4SrcOffset:], new[:])
		srcChanged = true
	}
	if equal4(buf[inner+ipv4DstOffset:], old) {
		copy(buf[inner+ipv4DstOffset:], new[:])
		dstChanged = true
	}
	if !srcChanged && !dstChanged {
		return
	}

	// 内层 IP 头校验和只覆盖内层头部（最多 60 字节），重算比增量省心。
	oldInner := binary.BigEndian.Uint16(buf[inner+ipv4ChecksumOff:])
	binary.BigEndian.PutUint16(buf[inner+ipv4ChecksumOff:], 0)
	newInner := checksum16(buf[inner : inner+innerHdr.headerLen])
	binary.BigEndian.PutUint16(buf[inner+ipv4ChecksumOff:], newInner)

	// 外层 ICMP 校验和覆盖整条 ICMP 消息，而这条消息可能被分片：我们手上
	// 也许只有首片，按可见范围重算就把整条消息的校验和写坏了，收端重组后
	// 整条差错作废（路径 MTU 发现因此失效）。改成增量更新：只把改动过的
	// 16 位字折进去，看不看得到整条消息都成立。
	//
	// 不做 0 → 0xFFFF 的规范化：那条规则属于 UDP（0 表示"发送端没算"），
	// ICMP 里 0 是合法校验和，增量结果与整条重算在反码算术下等价。
	sum := binary.BigEndian.Uint16(buf[icmp+icmpChecksumOff:])
	if srcChanged {
		sum = updateChecksum(sum, binary.BigEndian.Uint16(old[0:2]), binary.BigEndian.Uint16(new[0:2]))
		sum = updateChecksum(sum, binary.BigEndian.Uint16(old[2:4]), binary.BigEndian.Uint16(new[2:4]))
	}
	if dstChanged {
		sum = updateChecksum(sum, binary.BigEndian.Uint16(old[0:2]), binary.BigEndian.Uint16(new[0:2]))
		sum = updateChecksum(sum, binary.BigEndian.Uint16(old[2:4]), binary.BigEndian.Uint16(new[2:4]))
	}
	sum = updateChecksum(sum, oldInner, newInner)
	binary.BigEndian.PutUint16(buf[icmp+icmpChecksumOff:], sum)
}

// checksum16 返回 b 的 16 位反码校验和。调用方要先把 b 里的校验和字段置 0。
func checksum16(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// hasPseudoHeaderChecksum 报告该协议是否把地址算进校验和。
//
// 只列校园网里理论上可能出现的：SCTP、DCCP、UDP-Lite。
func hasPseudoHeaderChecksum(protocol byte) bool {
	switch protocol {
	case protocolSCTP, protocolDCCP, protocolUDPLite:
		return true
	}
	return false
}

// protocolName 返回协议名，用于日志。
func protocolName(protocol byte) string {
	switch protocol {
	case protocolTCP:
		return "TCP"
	case protocolUDP:
		return "UDP"
	case protocolSCTP:
		return "SCTP"
	case protocolDCCP:
		return "DCCP"
	case protocolUDPLite:
		return "UDP-Lite"
	}
	return fmt.Sprintf("协议 %d", protocol)
}

type ipv4Header struct {
	headerLen int
	totalLen  int
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
	protocolICMP    = 1
	// 同样把地址算进校验和的协议：改写地址后它们的校验和会失效，
	// 只提示一次（见 rewriteAddr 的 default 分支）。
	protocolDCCP    = 33
	protocolSCTP    = 132
	protocolUDPLite = 136
	tcpChecksumOff  = 16
	udpChecksumOff  = 6
	udpChecksumZero = 0
	// ICMP：8 字节头（类型、代码、校验和、其余部分），差错报文在这之后
	// 内嵌触发它的原始报文。
	icmpMinLen      = 8
	icmpChecksumOff = 2
	icmpEmbeddedOff = 8
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
		totalLen:  int(binary.BigEndian.Uint16(buf[2:])),
		protocol:  buf[9],
		fragField: binary.BigEndian.Uint16(buf[fragmentFieldAt:]),
	}, nil
}

// ipv4TotalLength 返回 IPv4 报文声明的总长度，并做基本合法性检查。
//
// 隧道下行是字节流：服务端可能把两个包写进一次 TLS 记录（粘包），
// 也可能把包分两次写（半包）。按总长度切包是唯一可靠的边界判断。
func ipv4TotalLength(buf []byte) (int, error) {
	hdr, err := parseIPv4(buf)
	if err != nil {
		return 0, err
	}
	if hdr.totalLen < hdr.headerLen {
		return 0, fmt.Errorf("IPv4 总长度 %d 小于头部长度 %d", hdr.totalLen, hdr.headerLen)
	}
	return hdr.totalLen, nil
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
