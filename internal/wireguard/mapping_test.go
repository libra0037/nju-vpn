package wireguard

import (
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
	if got := pkt[ipv4SrcOffset : ipv4SrcOffset+4]; !equal4(got, m.publicIP) {
		t.Fatalf("上行源地址 = %v, 期望 %v", net.IP(got), net.IP(m.publicIP[:]))
	}
	if got := pkt[ipv4DstOffset : ipv4DstOffset+4]; !equal4(got, dst) {
		t.Fatalf("上行目的地址被改坏了: %v", net.IP(got))
	}
	if ipChecksum(pkt[:20]) != 0 {
		t.Errorf("上行后 IP 头校验和错误: 0x%04x", binary.BigEndian.Uint16(pkt[ipv4ChecksumOff:]))
	}
	// 校验和字段本身参与求和：校验和正确时，伪头部加整包之和应为 0xffff。
	udp := pkt[20:]
	if got := fold(pseudoHeaderSum(m.publicIP, dst, protocolUDP, len(udp)) + sumBytes(udp)); got != 0 {
		t.Errorf("上行后 UDP 校验和校验失败，残差 = 0x%04x", got)
	}

	// 下行：目的应该是 peer，改完源仍是 public
	remote := [4]byte{202, 119, 32, 69}
	back := buildUDP(remote, m.publicIP, payload)
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
	pkt := buildUDP(m.publicIP, [4]byte{1, 1, 1, 1}, []byte("x"))
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

	// 找一个"改写后恰好是 0"的原始校验和：16 位上的变换是双射，必然存在。
	chosen := -1
	for c := 0; c <= 0xffff; c++ {
		v := updateChecksum(uint16(c),
			binary.BigEndian.Uint16(src[0:2]), binary.BigEndian.Uint16(m.publicIP[0:2]))
		v = updateChecksum(v,
			binary.BigEndian.Uint16(src[2:4]), binary.BigEndian.Uint16(m.publicIP[2:4]))
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
