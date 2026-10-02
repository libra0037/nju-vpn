package main

import (
	"context"
	"encoding/hex"
	"golang.zx2c4.com/wireguard/tun"
	"testing"
	"time"
)

func TestPacketProbeRequiresActualFragmentsAndExactMTU(t *testing.T) {
	var observer *packetTUN
	observedPeer := testPeer(t, false, func(base tun.Device) tun.Device {
		observer = &packetTUN{Device: base}
		return observer
	})
	report := probePackets(context.Background(), observedPeer, observer, testRunID, 5*time.Second)
	if !report.Passed || !report.HandshakeSeen || len(report.Checks) != 4 {
		t.Fatalf("边界流程失败: %+v", report)
	}
	for i, want := range []int{2, 3} {
		check := report.Checks[i+1]
		if check.Uplink.Fragments != want || !check.Uplink.FirstFragment || !check.Uplink.LastFragment || check.Bytes != 32 {
			t.Fatalf("实际分片不完整: %+v", check)
		}
	}
	icmp := report.Checks[3]
	if !icmp.Uplink.DF || icmp.Uplink.MaxBytes != 1400 || icmp.Bytes != 1380 {
		t.Fatalf("ICMP 未覆盖 DF/1400: %+v", icmp)
	}
}

func TestPacketChecksumFixedIPv4Fixture(t *testing.T) {
	// 固定字节样例的期望 9c1b 由独立 Python struct 的逐字相加给出。
	header, err := hex.DecodeString("450000731c46400040119c1bc0a80001c0a800c7")
	if err != nil {
		t.Fatal(err)
	}
	if packetChecksum(header) != 0 {
		t.Fatal("固定 IPv4 校验和未通过")
	}
	header[10], header[11] = 0, 0
	if got := packetChecksum(header); got != 0x9c1b {
		t.Fatalf("checksum=%04x", got)
	}
}

func TestPacketObserverRejectsShortAndRecordsFragmentFlags(t *testing.T) {
	observer := &packetTUN{}
	observer.observe([]byte{0x45}, true)
	packet := make([]byte, 20)
	packet[0] = 0x45
	packet[9] = 1
	observer.observe(packet, true) // 不足以含 ICMP type 时也不得越界。
	packet = make([]byte, 1400)
	packet[0] = 0x45
	packet[9] = 17
	packet[6] = 0x20
	observer.observe(packet, true)
	packet = make([]byte, 652)
	packet[0] = 0x45
	packet[9] = 17
	packet[7] = 172
	observer.observe(packet, true)
	up, _ := observer.counts(17)
	if up.Fragments != 2 || !up.FirstFragment || !up.LastFragment || up.MaxBytes != 1400 {
		t.Fatalf("分片观测错误: %+v", up)
	}
}

func TestFragmentProbeRejectsWrongReassemblyDigest(t *testing.T) {
	peer := testPeer(t, false, nil)
	result := probeFragmentUDP(context.Background(), peer, time.Second, 2000, "0000000000000000000000000000000000000000000000000000000000000000")
	if result.Passed || result.Error != "reassembled-content" || result.Bytes != 32 {
		t.Fatalf("错误摘要被接受: %+v", result)
	}
}
