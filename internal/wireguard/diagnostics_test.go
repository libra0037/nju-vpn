package wireguard

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/device"

	"github.com/libra0037/nju-vpn/internal/l3"
)

func TestMTUAndDiagnosticReasons(t *testing.T) {
	seen := make(map[string]bool)
	for reason, name := range dropReasonName {
		if name == "" || seen[name] || dropReasonText[reason] == "" {
			t.Fatal("诊断原因缺失或重复", reason)
		}
		seen[name] = true
	}
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	maxMTU := min(device.MaxContentSize, 65535-20-8-32) // 独立的 UDP/IPv4 与 WireGuard 32 字节封装判据。
	for _, mtu := range []int{1500, maxMTU} {
		d, err := NewDevice(DeviceOptions{MTU: mtu, PrivateKey: key})
		if err != nil {
			t.Fatalf("合法 MTU %d 被拒绝: %v", mtu, err)
		}
		if got, err := d.relay.MTU(); err != nil || got != mtu {
			t.Fatal("MTU 被静默截低", got, err)
		}
		d.Close()
	}
	if d, err := NewDevice(DeviceOptions{MTU: maxMTU + 1, PrivateKey: key}); err == nil {
		d.Close()
		t.Fatal("超过依赖缓冲上限仍被接受")
	}

	r := NewRelay(RelayOptions{MTU: 1500})
	t.Cleanup(func() { r.Close() })
	d := &Device{relay: r}
	ep := l3.New()
	r.InstallSession(ep, nil)
	var uplink []byte
	ep.SetUplink(func(pkt []byte) error { uplink = bytes.Clone(pkt); return nil })
	packet := ipv4Pkt([4]byte{172, 16, 0, 9}, [4]byte{10, 66, 66, 2}, 1480)
	if len(packet) != 1500 {
		t.Fatal("样例长度错误")
	}
	ep.Deliver(packet)
	if got := readOne(t, r, 1600); !bytes.Equal(got, packet) {
		t.Fatal("下行 1500 字节包未通过")
	}
	if _, err := r.Write([][]byte{packet}, 0); err != nil || !bytes.Equal(uplink, packet) {
		t.Fatal("上行 1500 字节包未通过", err)
	}
	oversized := ipv4Pkt([4]byte{172, 16, 0, 9}, [4]byte{10, 66, 66, 2}, 1481)
	ep.Deliver(oversized)
	r.Write([][]byte{oversized}, 0)
	if got := d.Diagnostics().Drops["mtu_exceeded"]; got != 2 {
		t.Fatal("MTU 拒绝须单独计数", got)
	}
	r.HoldDownlink(true)
	if got := d.Diagnostics(); !got.Configured || got.Ready {
		t.Fatal("装载对端不能冒充已握手")
	}
	r.peerGate.Load().seen.Store(true)
	snapshot := d.Diagnostics()
	if !snapshot.Ready {
		t.Fatal("握手就绪状态未暴露")
	}
	snapshot.Drops["mtu_exceeded"] = 77
	if d.Diagnostics().Drops["mtu_exceeded"] != 2 {
		t.Fatal("导出 map 可修改内部计数")
	}
	r.HoldDownlink(false)
	if got := d.Diagnostics(); got.Configured || got.Ready {
		t.Fatal("卸载对端仍报告就绪")
	}
}

func TestLateHandshakeCannotReadyReplacementPeer(t *testing.T) {
	r := NewRelay(RelayOptions{MTU: 1500})
	d := &Device{relay: r, closed: make(chan struct{}), watchDone: make(chan struct{})}
	r.HoldDownlink(true)
	old := r.peerGate.Load()
	entered, release := make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	t.Cleanup(func() { unblock.Do(func() { close(release) }); close(d.closed); <-d.watchDone; r.Close() })
	first := true // 只由实际的握手监视任务访问。
	go d.watchPeerHandshake(func() (deviceConfig, error) {
		if first {
			first = false
			close(entered)
			<-release
			return deviceConfig{lastHandshakeSec: 1}, nil
		}
		return deviceConfig{}, nil
	})
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("握手读取未开始")
	}
	r.HoldDownlink(false)
	r.HoldDownlink(true)
	unblock.Do(func() { close(release) })
	deadline := time.Now().Add(3 * time.Second)
	for !old.seen.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !old.seen.Load() {
		t.Fatal("没有实际执行迟到握手结果")
	}
	if got := d.Diagnostics(); !got.Configured || got.Ready {
		t.Fatal("旧握手结果归入新对端")
	}
}
