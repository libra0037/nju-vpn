package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"strings"
	"testing"

	"github.com/libra0037/nju-vpn/internal/l3"
	wg "github.com/libra0037/nju-vpn/internal/wireguard"
)

func TestLogSummaryIncludesActualRelayMTUDrop(t *testing.T) {
	var output bytes.Buffer
	originalWriter, originalFlags := log.Writer(), log.Flags()
	log.SetOutput(&output)
	log.SetFlags(log.LstdFlags)
	t.Cleanup(func() { log.SetOutput(originalWriter); log.SetFlags(originalFlags) })
	relay := wg.NewRelay(wg.RelayOptions{MTU: 1400})
	t.Cleanup(func() { relay.Close() })
	relay.InstallSession(l3.New(), nil)
	packet := make([]byte, 1401)
	packet[0], packet[8], packet[9] = 0x45, 64, 6
	binary.BigEndian.PutUint16(packet[2:4], 1401)
	copy(packet[12:16], []byte{10, 66, 66, 2})
	copy(packet[16:20], []byte{192, 0, 2, 1})
	if _, err := relay.Write([][]byte{packet}, 0); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 1 {
		t.Fatal("实际丢包没有产生一条限速日志")
	}
	event, ok := parseLogEvent(lines[0])
	if !ok || event.Kind != "relay_drop" || event.Reason != "mtu_exceeded" || event.Count != 1 {
		t.Fatal("当前产品 MTU 丢包日志被遗漏", event, ok)
	}
}
