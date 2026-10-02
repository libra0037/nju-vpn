package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// 固定摘要由 Python hashlib 对 prefix + bytes(i % 251) 的独立样例给出。
const (
	fragment2000Hash = "8eef584112529c4cbd25f52b46482566914b8197ff116b8304cfdcbe5ade9896"
	fragment4000Hash = "da4b50a7ff595d634576afbc81fa5d9e4f03bf55806d7e29020c63acca66807c"
)

type packetCounts struct {
	Packets       int  `json:"packets"`
	Fragments     int  `json:"fragments"`
	FirstFragment bool `json:"first_fragment_seen"`
	LastFragment  bool `json:"last_fragment_seen"`
	MaxBytes      int  `json:"max_ip_bytes"`
	DF            bool `json:"dont_fragment_seen"`
}

type packetTUN struct {
	tun.Device
	mu       sync.Mutex
	uplink   [256]packetCounts
	downlink [256]packetCounts
}

func (t *packetTUN) observe(packet []byte, uplink bool) {
	if len(packet) < 20 || packet[0] != 0x45 {
		return
	}
	flags := binary.BigEndian.Uint16(packet[6:8])
	if uplink && len(packet) >= 28 && packet[9] == 1 && packet[20] == 8 {
		// ICMP 边界用例明确要求 DF；TUN 修改当前独占缓冲并重算 IP 校验和。
		flags |= 0x4000
		binary.BigEndian.PutUint16(packet[6:8], flags)
		packet[10], packet[11] = 0, 0
		binary.BigEndian.PutUint16(packet[10:12], packetChecksum(packet[:20]))
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	counts := &t.downlink[packet[9]]
	if uplink {
		counts = &t.uplink[packet[9]]
	}
	counts.Packets++
	counts.MaxBytes = max(counts.MaxBytes, len(packet))
	counts.DF = counts.DF || flags&0x4000 != 0
	if flags&0x3fff != 0 {
		counts.Fragments++
		counts.FirstFragment = counts.FirstFragment || flags&0x1fff == 0
		counts.LastFragment = counts.LastFragment || flags&0x2000 == 0
	}
}

func (t *packetTUN) Read(buffers [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.Device.Read(buffers, sizes, offset)
	for i := 0; i < n; i++ {
		t.observe(buffers[i][offset:offset+sizes[i]], true)
	}
	return n, err
}

func (t *packetTUN) Write(buffers [][]byte, offset int) (int, error) {
	for _, packet := range buffers {
		t.observe(packet[offset:], false)
	}
	return t.Device.Write(buffers, offset)
}

func (t *packetTUN) reset() {
	t.mu.Lock()
	t.uplink, t.downlink = [256]packetCounts{}, [256]packetCounts{}
	t.mu.Unlock()
}

func (t *packetTUN) counts(protocol byte) (packetCounts, packetCounts) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.uplink[protocol], t.downlink[protocol]
}

func packetChecksum(packet []byte) uint16 {
	var sum uint32
	for len(packet) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(packet))
		packet = packet[2:]
	}
	if len(packet) != 0 {
		sum += uint32(packet[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

type packetCheck struct {
	checkResult
	Uplink   packetCounts `json:"uplink"`
	Downlink packetCounts `json:"downlink"`
}

type packetReport struct {
	RunID         string        `json:"run_id"`
	Passed        bool          `json:"passed"`
	MTU           int           `json:"mtu"`
	HandshakeSeen bool          `json:"wireguard_handshake_seen"`
	Checks        []packetCheck `json:"checks"`
}

func probePackets(ctx context.Context, peer *directPeer, observer *packetTUN, runID string, budget time.Duration) (report packetReport) {
	report = packetReport{RunID: runID, MTU: mtu}
	defer func() {
		report.HandshakeSeen = handshakeSeen(peer)
		report.Passed = report.Passed && report.HandshakeSeen
	}()
	health := probeHTTP(ctx, peer, runID, budget, "health", "GET", "/health", "", 20)
	report.Checks = append(report.Checks, packetCheck{checkResult: health})
	if !health.Passed {
		return report
	}
	for _, test := range []struct {
		size   int
		digest string
	}{{2000, fragment2000Hash}, {4000, fragment4000Hash}} {
		observer.reset()
		check := probeFragmentUDP(ctx, peer, budget, test.size, test.digest)
		check.Uplink, check.Downlink = observer.counts(17)
		if check.Passed && (check.Uplink.Fragments < 2 || !check.Uplink.FirstFragment || !check.Uplink.LastFragment || check.Uplink.MaxBytes > mtu) {
			check.Passed, check.Error = false, "fragment-evidence"
		}
		report.Checks = append(report.Checks, check)
		if !check.Passed {
			return report
		}
	}
	observer.reset()
	check := probeICMP(ctx, peer, budget)
	check.Uplink, check.Downlink = observer.counts(1)
	if check.Passed && (!check.Uplink.DF || check.Uplink.MaxBytes != mtu || check.Uplink.Fragments != 0 || check.Downlink.Fragments != 0) {
		check.Passed, check.Error = false, "icmp-mtu-evidence"
	}
	report.Checks = append(report.Checks, check)
	report.Passed = check.Passed
	return report
}

func probeFragmentUDP(parent context.Context, peer *directPeer, budget time.Duration, size int, digest string) (result packetCheck) {
	started := time.Now()
	result.Name, result.BudgetMS = fmt.Sprintf("udp-fragments-%d", size), budget.Milliseconds()
	defer func() { result.ElapsedMS = time.Since(started).Milliseconds() }()
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	connection, err := peer.net.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(peer.target, udpPort))
	if err != nil {
		result.Error = classify(err)
		return result
	}
	defer closeOnCancel(ctx, connection)()
	deadline, _ := ctx.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		result.Error = classify(err)
		return result
	}
	body := payload(size, 251)
	copy(body, "NJUVPN-SHA256:")
	if n, err := connection.Write(body); err != nil || n != len(body) {
		result.Error = "udp-write"
		return result
	}
	received := make([]byte, 33)
	n, err := connection.Read(received)
	result.Bytes = int64(n)
	if err != nil {
		result.Error = classify(err)
		return result
	}
	if n != 32 || hex.EncodeToString(received[:n]) != digest {
		result.Error = "reassembled-content"
		return result
	}
	result.Passed = true
	return result
}

func probeICMP(parent context.Context, peer *directPeer, budget time.Duration) (result packetCheck) {
	started := time.Now()
	result.Name, result.BudgetMS = "icmp-1372-df-mtu-1400", budget.Milliseconds()
	defer func() { result.ElapsedMS = time.Since(started).Milliseconds() }()
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	connection, err := peer.net.DialPingAddr(netip.Addr{}, peer.target)
	if err != nil {
		result.Error = classify(err)
		return result
	}
	defer closeOnCancel(ctx, connection)()
	deadline, _ := ctx.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		result.Error = classify(err)
		return result
	}
	message := make([]byte, 8+1372)
	message[0], message[7] = 8, 1
	copy(message[8:], payload(1372, 251))
	binary.BigEndian.PutUint16(message[2:4], packetChecksum(message))
	if n, err := connection.Write(message); err != nil || n != len(message) {
		result.Error = "icmp-write"
		return result
	}
	received := make([]byte, len(message)+1)
	n, err := connection.Read(received)
	result.Bytes = int64(n)
	if err != nil {
		result.Error = classify(err)
		return result
	}
	// 栈为 ICMP socket 分配 identifier；独立验证类型、序号与固定正文。
	if n != len(message) || received[0] != 0 || received[1] != 0 || received[6] != 0 || received[7] != 1 || packetChecksum(received[:n]) != 0 || !bytes.Equal(received[8:n], message[8:]) {
		result.Error = "icmp-content"
		return result
	}
	result.Passed = true
	return result
}

// 返回的收尾函数等待已触发的取消回调，避免把 Close 协程留给调用者。
func closeOnCancel(ctx context.Context, connection io.Closer) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { connection.Close(); close(done) })
	return func() {
		if !stop() {
			<-done
		}
		connection.Close()
	}
}
