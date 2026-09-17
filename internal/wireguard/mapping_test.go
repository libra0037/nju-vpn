package wireguard

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// ipChecksum 按 RFC 1071 整包重算 IP 头校验和，用来验证增量更新是否正确。
func ipChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i:]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// pseudoHeaderSum 计算传输层校验和需要的伪头部之和。
func pseudoHeaderSum(src, dst [4]byte, proto byte, length int) uint32 {
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(src[0:2]))
	sum += uint32(binary.BigEndian.Uint16(src[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dst[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dst[2:4]))
	sum += uint32(proto)
	sum += uint32(length)
	return sum
}

func sumBytes(b []byte) uint32 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

func fold(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// buildUDP 造一个 UDP/IPv4 报文。
func buildUDP(src, dst [4]byte, payload []byte) []byte {
	udpLen := 8 + len(payload)
	pkt := make([]byte, 20+udpLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	pkt[9] = protocolUDP
	copy(pkt[ipv4SrcOffset:], src[:])
	copy(pkt[ipv4DstOffset:], dst[:])
	binary.BigEndian.PutUint16(pkt[ipv4ChecksumOff:], ipChecksum(pkt[:20]))

	udp := pkt[20:]
	binary.BigEndian.PutUint16(udp[0:], 12345)
	binary.BigEndian.PutUint16(udp[2:], 53)
	binary.BigEndian.PutUint16(udp[4:], uint16(udpLen))
	copy(udp[8:], payload)

	sum := pseudoHeaderSum(src, dst, protocolUDP, udpLen) + sumBytes(udp)
	csum := fold(sum)
	if csum == 0 {
		csum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[udpChecksumOff:], csum)
	return pkt
}

func TestMapperUplinkDownlink(t *testing.T) {
	peer := net.IPv4(10, 66, 66, 2)
	public := net.IPv4(172, 29, 32, 160)
	m, err := NewMapper(peer, public)
	if err != nil {
		t.Fatal(err)
	}

	dst := [4]byte{202, 119, 32, 69}
	payload := []byte("hello njuvpn")

	// 上行：源是 peer，改完应该是 public
	pkt := buildUDP(m.peerIP, dst, payload)
	if _, err := m.Uplink(pkt); err != nil {
		t.Fatalf("uplink: %v", err)
	}
	public4 := mustPublic(t, m)
	if got := pkt[ipv4SrcOffset : ipv4SrcOffset+4]; !equal4(got, public4) {
		t.Fatalf("上行源地址 = %v, 期望 %v", net.IP(got), net.IP(public4[:]))
	}
	if got := pkt[ipv4DstOffset : ipv4DstOffset+4]; !equal4(got, dst) {
		t.Fatalf("上行目的地址被改坏了: %v", net.IP(got))
	}
	if ipChecksum(pkt[:20]) != 0 {
		t.Errorf("上行后 IP 头校验和错误: 0x%04x", binary.BigEndian.Uint16(pkt[ipv4ChecksumOff:]))
	}
	// 校验和字段本身参与求和：校验和正确时，伪头部加整包之和应为 0xffff。
	udp := pkt[20:]
	if got := fold(pseudoHeaderSum(public4, dst, protocolUDP, len(udp)) + sumBytes(udp)); got != 0 {
		t.Errorf("上行后 UDP 校验和校验失败，残差 = 0x%04x", got)
	}

	// 下行：目的应该是 peer，改完源仍是 public
	remote := [4]byte{202, 119, 32, 69}
	back := buildUDP(remote, public4, payload)
	if _, err := m.Downlink(back); err != nil {
		t.Fatalf("downlink: %v", err)
	}
	if got := back[ipv4DstOffset : ipv4DstOffset+4]; !equal4(got, m.peerIP) {
		t.Fatalf("下行目的地址 = %v, 期望 %v", net.IP(got), net.IP(m.peerIP[:]))
	}
	if got := back[ipv4SrcOffset : ipv4SrcOffset+4]; !equal4(got, remote) {
		t.Fatalf("下行源地址被改坏了: %v", net.IP(got))
	}
	if ipChecksum(back[:20]) != 0 {
		t.Errorf("下行后 IP 头校验和错误")
	}
	udp = back[20:]
	if got := fold(pseudoHeaderSum(remote, m.peerIP, protocolUDP, len(udp)) + sumBytes(udp)); got != 0 {
		t.Errorf("下行后 UDP 校验和校验失败，残差 = 0x%04x", got)
	}
}

func TestMapperRejectsWrongDirection(t *testing.T) {
	m, err := NewMapper(net.IPv4(10, 66, 66, 2), net.IPv4(172, 29, 32, 160))
	if err != nil {
		t.Fatal(err)
	}
	pkt := buildUDP(mustPublic(t, m), [4]byte{1, 1, 1, 1}, []byte("x"))
	if _, err := m.Uplink(pkt); err == nil {
		t.Error("源地址不是 peer 的包不应被上行改写")
	}
}

// 回归：改写地址后 UDP 校验和可能算成 0x0000，而 RFC 768 规定线上要写全 1。
//
// 0x0000 的含义是"发送端没算校验和"，接收端会跳过校验——等于给对方一个
// 可能已损坏的包（实测 100 万个随机样本里约 24 次会踩到）。
func TestUDPChecksumZeroBecomesAllOnes(t *testing.T) {
	m, err := NewMapper(net.IPv4(10, 66, 66, 2), net.IPv4(172, 29, 56, 18))
	if err != nil {
		t.Fatal(err)
	}
	src := m.peerIP
	dst := [4]byte{202, 119, 32, 69}
	public4 := mustPublic(t, m)

	// 找一个"改写后恰好是 0"的原始校验和：16 位上的变换是双射，必然存在。
	chosen := -1
	for c := 0; c <= 0xffff; c++ {
		v := updateChecksum(uint16(c),
			binary.BigEndian.Uint16(src[0:2]), binary.BigEndian.Uint16(public4[0:2]))
		v = updateChecksum(v,
			binary.BigEndian.Uint16(src[2:4]), binary.BigEndian.Uint16(public4[2:4]))
		if v == 0 {
			chosen = c
			break
		}
	}
	if chosen < 0 {
		t.Fatal("没找到会变成 0 的校验和，测试前提不成立")
	}

	pkt := buildUDP(src, dst, []byte("probe"))
	binary.BigEndian.PutUint16(pkt[20+udpChecksumOff:], uint16(chosen))
	if _, err := m.Uplink(pkt); err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint16(pkt[20+udpChecksumOff:]); got != 0xffff {
		t.Errorf("改写后校验和 = 0x%04x，应为 0xffff", got)
	}
}

func TestUDPZeroChecksumUntouched(t *testing.T) {
	m, err := NewMapper(net.IPv4(10, 66, 66, 2), net.IPv4(172, 29, 32, 160))
	if err != nil {
		t.Fatal(err)
	}
	pkt := buildUDP(m.peerIP, [4]byte{1, 1, 1, 1}, []byte("x"))
	binary.BigEndian.PutUint16(pkt[20+udpChecksumOff:], 0)
	if _, err := m.Uplink(pkt); err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint16(pkt[20+udpChecksumOff:]); got != 0 {
		t.Errorf("UDP 校验和本为 0，被改成了 0x%04x", got)
	}
}

// mustPublic 取映射当前使用的隧道地址，供测试断言用。
func mustPublic(t *testing.T, m *Mapper) [4]byte {
	t.Helper()
	addr, err := m.currentPublic()
	if err != nil {
		t.Fatalf("取隧道地址: %v", err)
	}
	return addr
}

// buildICMPError 造一个携带内嵌原始报文的 ICMP 差错报文。
func buildICMPError(src, dst [4]byte, typ, code byte, inner []byte) []byte {
	pkt := make([]byte, ipv4MinHeader+icmpMinLen+len(inner))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	pkt[9] = protocolICMP
	copy(pkt[ipv4SrcOffset:], src[:])
	copy(pkt[ipv4DstOffset:], dst[:])
	binary.BigEndian.PutUint16(pkt[ipv4ChecksumOff:], ipChecksum(pkt[:ipv4MinHeader]))

	icmp := pkt[ipv4MinHeader:]
	icmp[0] = typ
	icmp[1] = code
	copy(icmp[icmpEmbeddedOff:], inner)
	binary.BigEndian.PutUint16(icmp[icmpChecksumOff:], ipChecksum(icmp))
	return pkt
}

// checksumOK 验证从 off 开始的 addend 长度区域（含校验和字段）校验通过。
func checksumOK(pkt []byte, at int, length int) bool {
	var sum uint32
	for i := at; i+1 < at+length; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i:]))
	}
	if (length)%2 == 1 {
		sum += uint32(pkt[at+length-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum) == 0xffff
}

// TestMapperRewritesICMPErrorInner 验证 ICMP 差错报文里内嵌的原始报文头也跟着
// 改写地址与校验和。
//
// 路径 MTU 发现靠"需要分片"这类差错把触发它的原始报文头带回来，协议栈按
// 内层的四元组把差错关联回套接字：内层地址仍是我们改写前的地址时，差错对不
// 上号被丢掉，大包路径就此黑掉，表现是"发出去了没回应"。
func TestMapperRewritesICMPErrorInner(t *testing.T) {
	m, err := NewMapper(net.IPv4(10, 66, 66, 2), net.IPv4(172, 29, 32, 160))
	if err != nil {
		t.Fatal(err)
	}
	peer4 := m.peerIP
	public4 := mustPublic(t, m)
	remote := [4]byte{202, 119, 32, 69}
	const innerAt = ipv4MinHeader + icmpEmbeddedOff

	t.Run("下行差错改内层源地址", func(t *testing.T) {
		// 校园网路由器回给"客户端发出的那个包"的差错：外层目的地址是隧道
		// 地址，内层原始报文的源地址也是隧道地址（改写过之后就是这个）。
		// 真差错只带原始报文的前 28 字节，这里照做。
		inner := buildUDP(public4, remote, []byte("big"))[:28]
		pkt := buildICMPError(remote, public4, 3, 4, inner)
		if _, err := m.Downlink(pkt); err != nil {
			t.Fatalf("downlink: %v", err)
		}
		if got := pkt[ipv4DstOffset : ipv4DstOffset+4]; !equal4(got, peer4) {
			t.Errorf("外层目的地址 = %v，期望 %v", net.IP(got), net.IP(peer4[:]))
		}
		if got := pkt[innerAt+ipv4SrcOffset : innerAt+ipv4SrcOffset+4]; !equal4(got, peer4) {
			t.Errorf("内层源地址 = %v，期望 %v", net.IP(got), net.IP(peer4[:]))
		}
		if got := pkt[innerAt+ipv4DstOffset : innerAt+ipv4DstOffset+4]; !equal4(got, remote) {
			t.Errorf("内层目的地址被改坏了: %v", net.IP(got))
		}
		if !checksumOK(pkt, 0, ipv4MinHeader) {
			t.Error("外层 IP 头校验和没过")
		}
		if !checksumOK(pkt, innerAt, ipv4MinHeader) {
			t.Error("内层 IP 头校验和没过")
		}
		if !checksumOK(pkt, ipv4MinHeader, len(pkt)-ipv4MinHeader) {
			t.Error("ICMP 校验和没过（它覆盖内嵌报文）")
		}
	})

	t.Run("上行差错改内层目的地址", func(t *testing.T) {
		// 客户端协议栈对"收到的包"回差错：外层源地址是 peer，内层原始
		// 报文的目的是 peer（它看到的就是这个地址）。
		inner := buildUDP(remote, peer4, []byte("hi"))[:28]
		pkt := buildICMPError(peer4, remote, 3, 3, inner)
		if _, err := m.Uplink(pkt); err != nil {
			t.Fatalf("uplink: %v", err)
		}
		if got := pkt[ipv4SrcOffset : ipv4SrcOffset+4]; !equal4(got, public4) {
			t.Errorf("外层源地址 = %v，期望 %v", net.IP(got), net.IP(public4[:]))
		}
		if got := pkt[innerAt+ipv4DstOffset : innerAt+ipv4DstOffset+4]; !equal4(got, public4) {
			t.Errorf("内层目的地址 = %v，期望 %v", net.IP(got), net.IP(public4[:]))
		}
		if got := pkt[innerAt+ipv4SrcOffset : innerAt+ipv4SrcOffset+4]; !equal4(got, remote) {
			t.Errorf("内层源地址被改坏了: %v", net.IP(got))
		}
		if !checksumOK(pkt, ipv4MinHeader, len(pkt)-ipv4MinHeader) {
			t.Error("ICMP 校验和没过（它覆盖内嵌报文）")
		}
	})

	t.Run("回显报文不碰载荷", func(t *testing.T) {
		// 回显请求（类型 8）的"其余部分"是标识与序号，后面跟的是数据，
		// 不是内嵌报文：即使看着像 IP 头也不能动。
		inner := buildUDP(public4, remote, []byte("x"))
		pkt := buildICMPError(peer4, remote, 8, 0, inner)
		want := append([]byte(nil), pkt...)
		if _, err := m.Uplink(pkt); err != nil {
			t.Fatalf("uplink: %v", err)
		}
		if got := pkt[ipv4SrcOffset : ipv4SrcOffset+4]; !equal4(got, public4) {
			t.Errorf("外层源地址 = %v，期望 %v", net.IP(got), net.IP(public4[:]))
		}
		if got := pkt[ipv4MinHeader:]; !bytes.Equal(got, want[ipv4MinHeader:]) {
			t.Error("回显报文的载荷被改动了")
		}
	})

	t.Run("内层被截断就原样放过", func(t *testing.T) {
		inner := buildUDP(public4, remote, []byte("big"))[:ipv4MinHeader-4]
		pkt := buildICMPError(remote, public4, 11, 0, inner)
		if _, err := m.Downlink(pkt); err != nil {
			t.Fatalf("downlink: %v", err)
		}
		// 外层照常改写；不完整的"内层"不动，也不该崩。
		if got := pkt[ipv4DstOffset : ipv4DstOffset+4]; !equal4(got, peer4) {
			t.Errorf("外层目的地址 = %v，期望 %v", net.IP(got), net.IP(peer4[:]))
		}
	})
}

// TestMapperICMPErrorFragmentChecksum 回归：ICMP 差错报文被分片时，外层校验和
// 必须按整条消息更新。
//
// ICMP 校验和覆盖整条 ICMP 消息，而分片之后手上可能只有首片：按可见范围
// 重算会把校验和写坏，收端重组后整条差错作废，路径 MTU 发现跟着失效。
// 这里把整条消息拆成两片、只改首片，再按重组后的字节验证校验和——退回
// 重算的写法即失败（已经反向验证过）。
func TestMapperICMPErrorFragmentChecksum(t *testing.T) {
	m, err := NewMapper(net.IPv4(10, 66, 66, 2), net.IPv4(172, 29, 32, 160))
	if err != nil {
		t.Fatal(err)
	}
	peer4 := m.peerIP
	public4 := mustPublic(t, m)
	remote := [4]byte{202, 119, 32, 69}

	// 内嵌一整个大包，让差错报文（20 头 + 8 ICMP 头 + 内层）越过分片点。
	inner := buildUDP(public4, remote, bytes.Repeat([]byte("x"), 976))
	full := buildICMPError(remote, public4, 3, 4, inner)

	// 分片按 8 字节对齐：首片携带前 960 字节载荷，其余进后续片。
	const firstPayload = 960
	frag1 := append([]byte(nil), full[:ipv4MinHeader+firstPayload]...)
	frag2 := append([]byte(nil), full[:ipv4MinHeader]...)
	frag2 = append(frag2, full[ipv4MinHeader+firstPayload:]...)
	// 首片：MF=1、偏移 0，总长改成本片长度，IP 头校验和重算。
	binary.BigEndian.PutUint16(frag1[2:], uint16(len(frag1)))
	binary.BigEndian.PutUint16(frag1[fragmentFieldAt:], 0x2000)
	binary.BigEndian.PutUint16(frag1[ipv4ChecksumOff:], 0)
	binary.BigEndian.PutUint16(frag1[ipv4ChecksumOff:], ipChecksum(frag1[:ipv4MinHeader]))
	// 后续片：只带偏移。
	binary.BigEndian.PutUint16(frag2[2:], uint16(len(frag2)))
	binary.BigEndian.PutUint16(frag2[fragmentFieldAt:], uint16(firstPayload/8))
	binary.BigEndian.PutUint16(frag2[ipv4ChecksumOff:], 0)
	binary.BigEndian.PutUint16(frag2[ipv4ChecksumOff:], ipChecksum(frag2[:ipv4MinHeader]))

	frag2Before := append([]byte(nil), frag2[ipv4MinHeader:]...)
	if _, err := m.Downlink(frag1); err != nil {
		t.Fatalf("downlink 首片: %v", err)
	}
	if _, err := m.Downlink(frag2); err != nil {
		t.Fatalf("downlink 后续片: %v", err)
	}

	// 后续片里没有 ICMP 头：载荷一个字节都不能动。
	if !bytes.Equal(frag2[ipv4MinHeader:], frag2Before) {
		t.Error("非首片的载荷被改动了")
	}
	// 首片里的内层地址确实改写了，否则这条用例什么也没验证。
	innerAt := ipv4MinHeader + icmpEmbeddedOff
	if got := frag1[innerAt+ipv4SrcOffset : innerAt+ipv4SrcOffset+4]; !equal4(got, peer4) {
		t.Fatalf("首片里的内层源地址 = %v，期望 %v", net.IP(got), net.IP(peer4[:]))
	}

	// 收端看到的是重组后的消息：按它验证 ICMP 校验和。
	reassembled := append(append([]byte(nil), frag1[ipv4MinHeader:]...), frag2[ipv4MinHeader:]...)
	if !checksumOK(reassembled, 0, len(reassembled)) {
		t.Fatal("重组后的 ICMP 校验和不对：必须按整条消息增量更新，不能按可见范围重算")
	}
}
