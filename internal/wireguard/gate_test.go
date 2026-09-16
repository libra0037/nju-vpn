package wireguard

import (
	"encoding/hex"
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

// TestDownlinkGateOpensOnHandshake 验证下行闩锁由“握手完成”松开，而不是等客户端
// 先送来数据包。
//
// 客户端只发保活（空包不进 TUN）时，老判据永远等不到那一刻：纯下载的客户端
// 会一直卡在闩锁前面，表现是隧道 up 但什么都不通。
func TestDownlinkGateOpensOnHandshake(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 的 ring bind 需要管理员权限，跳过回环测试")
	}

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

	// 服务端：承载设备。会话与映射先不挂，只验证闩锁。
	port := freeUDPPort(t)
	server, err := NewDevice(DeviceOptions{MTU: 1420, PrivateKey: serverPriv, ListenPort: port})
	if err != nil {
		t.Fatalf("创建承载设备失败: %v", err)
	}
	defer server.Close()
	if err := server.SetPeer(clientPub, net.ParseIP("10.66.66.2")); err != nil {
		t.Fatalf("配置 peer 失败: %v", err)
	}
	if !server.relay.hold.Load() {
		t.Fatal("装了 peer 之后下行闩锁应当是闭合的")
	}
	if server.relay.peerSeen.Load() {
		t.Fatal("客户端还没露面，闩锁不该松开")
	}

	// 客户端：一台真实设备，只配保活，不发任何数据。
	clientTun := newMemoryTun()
	clientDev := device.NewDevice(clientTun, conn.NewDefaultBind(),
		device.NewLogger(device.LogLevelError, "client: "))
	defer clientDev.Close()
	clientConf := fmt.Sprintf(
		"private_key=%s\nlisten_port=0\nreplace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=1\n",
		hex.EncodeToString(clientPriv[:]), hex.EncodeToString(serverPub[:]), port)
	if err := clientDev.IpcSet(clientConf); err != nil {
		t.Fatalf("配置客户端失败: %v", err)
	}
	if err := clientDev.Up(); err != nil {
		t.Fatalf("启动客户端失败: %v", err)
	}

	// 闩锁应当在一两秒内松开（探测间隔 200ms）。
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if server.relay.peerSeen.Load() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("客户端完成握手之后下行闩锁仍然闭着（老判据只认客户端数据包）")
}

// TestMapperFollowsAddressChange 验证映射用的是“当前”隧道地址：服务端中途下发
// 新地址之后，上行改写与新地址匹配、下行按新地址放行、旧地址不再被认。
func TestMapperFollowsAddressChange(t *testing.T) {
	current := net.IPv4(172, 16, 0, 9)
	m, err := NewDynamicMapper(net.IPv4(10, 66, 66, 2), func() net.IP { return current })
	if err != nil {
		t.Fatal(err)
	}

	dst := [4]byte{202, 119, 32, 69}
	newAddr := net.IPv4(172, 16, 9, 9)
	current = newAddr

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
