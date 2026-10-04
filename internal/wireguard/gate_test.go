package wireguard

import (
	"encoding/hex"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/l3"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

// TestDownlinkGateOpensOnHandshake 验证下行闩锁由“握手完成”松开，而不是等对端
// 先送来数据包。
//
// 对端只发保活（空包不进 TUN）时，老判据永远等不到那一刻：纯下载的对端
// 会一直卡在闩锁前面，表现是隧道 up 但什么都不通。
func TestDownlinkGateOpensOnHandshake(t *testing.T) {

	serverPriv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	serverPub, err := serverPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	clientPriv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	clientPub, err := clientPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	// 承载层：承载设备。会话与映射先不挂，只验证闩锁。
	port := freeUDPPort(t)
	server, err := NewDevice(DeviceOptions{MTU: 1400, PrivateKey: serverPriv, ListenPort: port})
	if err != nil {
		t.Fatalf("创建承载设备失败: %v", err)
	}
	defer server.Close()
	if err := server.SetPeer(clientPub, net.ParseIP("10.66.66.2")); err != nil {
		t.Fatalf("配置 peer 失败: %v", err)
	}
	if server.relay.peerGate.Load() == nil {
		t.Fatal("装了 peer 之后下行闩锁应当是闭合的")
	}
	if server.relay.peerGate.Load().seen.Load() {
		t.Fatal("对端还没露面，闩锁不该松开")
	}

	// 对端：一台真实设备，只配保活，不发任何数据。
	clientTun := newMemoryTun()
	clientDev := device.NewDevice(clientTun, conn.NewDefaultBind(),
		device.NewLogger(device.LogLevelError, "client: "))
	defer clientDev.Close()
	clientConf := fmt.Sprintf(
		"private_key=%s\nlisten_port=0\nreplace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=1\n",
		hex.EncodeToString(clientPriv[:]), hex.EncodeToString(serverPub[:]), port)
	if err := clientDev.IpcSet(clientConf); err != nil {
		t.Fatalf("配置对端失败: %v", err)
	}
	if err := clientDev.Up(); err != nil {
		t.Fatalf("启动对端失败: %v", err)
	}

	// 闩锁应当在一两秒内松开（探测间隔 200ms）。
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if server.relay.peerGate.Load().seen.Load() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("对端完成握手之后下行闩锁仍然闭着（老判据只认对端数据包）")
}

// TestMapperFollowsAddressChange 验证映射用的是“当前”隧道地址：服务端中途下发
// 新地址之后，上行改写与新地址匹配、下行按新地址放行、旧地址不再被认。
func TestMapperFollowsAddressChange(t *testing.T) {
	// 地址来源就是生产上的那一个（端点的原子量），不是测试自己搓的回调。
	ep := l3.New()
	ep.SetLocalAddr(net.IPv4(172, 16, 0, 9))
	m, err := NewDynamicMapper(net.IPv4(10, 66, 66, 2), ep.LocalAddr4)
	if err != nil {
		t.Fatal(err)
	}

	dst := [4]byte{202, 119, 32, 69}
	newAddr := net.IPv4(172, 16, 9, 9)
	// 服务端中途下发新地址。
	ep.SetLocalAddr(newAddr)

	pkt := buildUDP(m.peerIP, dst, []byte("x"))
	if _, err := m.Uplink(pkt); err != nil {
		t.Fatalf("uplink: %v", err)
	}
	if got := [4]byte{pkt[12], pkt[13], pkt[14], pkt[15]}; got != [4]byte{172, 16, 9, 9} {
		t.Fatalf("上行源地址 = %v，期望新地址 %v", got, newAddr)
	}

	back := buildUDP(dst, [4]byte{172, 16, 9, 9}, []byte("y"))
	if _, err := m.Downlink(back); err != nil {
		t.Fatalf("下行应当按新地址放行: %v", err)
	}
	if got := [4]byte{back[16], back[17], back[18], back[19]}; got != [4]byte{10, 66, 66, 2} {
		t.Fatalf("下行目的地址 = %v，期望 peer 地址", got)
	}

	stale := buildUDP(dst, [4]byte{172, 16, 0, 9}, []byte("z"))
	if _, err := m.Downlink(stale); err == nil {
		t.Fatal("旧地址的下行包应当被拒（映射已经切到新地址）")
	}
}

// TestProbeIntervalBacksOff 钉住探测节奏。
//
// 只有"有会话、还没见到握手"这一段才短间隔探测；闩锁开着（没有会话，或对端
// 已经露面）时一律用上限等着——老实现把这两种情况都重置回 200ms，于是稳态
// 下每秒醒五次，读到进程结束。
func TestProbeIntervalBacksOff(t *testing.T) {
	if got := probeInterval(false, false, handshakeSettleMax); got != handshakeSettleMax {
		t.Errorf("没有会话时下一次探测间隔 %v，期望 %v", got, handshakeSettleMax)
	}
	if got := probeInterval(true, true, handshakeSettleMax); got != handshakeSettleMax {
		t.Errorf("对端已露面时 %v，期望 %v", got, handshakeSettleMax)
	}
	if got := probeInterval(true, false, handshakeSettleInterval); got != 2*handshakeSettleInterval {
		t.Errorf("探测阶段应当退避，得到 %v", got)
	}
	if got := probeInterval(true, false, handshakeSettleMax); got != handshakeSettleMax {
		t.Errorf("退避不该超过上限，得到 %v", got)
	}
}
