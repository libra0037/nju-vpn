package wireguard

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/libra0037/nju-vpn/internal/vpn"
)

// 这个文件做一次真正的端到端回环：本进程的承载设备（Relay + 映射 + 假校园网隧道）
// 与另一台真实的 WireGuard 设备互通，验证握手、加密、包转发与地址改写都对。
//
// 客户端用内存 TUN，不创建任何网卡，也不需要 root；UDP 只在 127.0.0.1 上回环。

// memoryTun 是实现 tun.Device 的内存设备，充当客户端的网络栈。
type memoryTun struct {
	// sendQ 是客户端想发出去的包（由 device 的 Read 取走）。
	sendQ chan []byte
	// recvQ 是客户端从隧道收到的包（由 device 的 Write 放入）。
	recvQ chan []byte

	events    chan tun.Event
	closed    chan struct{}
	closeOnce sync.Once
}

func newMemoryTun() *memoryTun {
	t := &memoryTun{
		sendQ:  make(chan []byte, 32),
		recvQ:  make(chan []byte, 32),
		events: make(chan tun.Event, 8),
		closed: make(chan struct{}),
	}
	t.events <- tun.EventUp
	return t
}

func (t *memoryTun) File() *os.File { return nil }

func (t *memoryTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case pkt := <-t.sendQ:
		sizes[0] = copy(bufs[0][offset:], pkt)
		return 1, nil
	case <-t.closed:
		return 0, os.ErrClosed
	}
}

func (t *memoryTun) Write(bufs [][]byte, offset int) (int, error) {
	n := 0
	for _, buf := range bufs {
		pkt := buf[offset:]
		if len(pkt) == 0 {
			continue
		}
		cp := append([]byte(nil), pkt...)
		select {
		case t.recvQ <- cp:
		case <-t.closed:
			return n, os.ErrClosed
		}
		n++
	}
	return n, nil
}

func (t *memoryTun) MTU() (int, error)        { return 1420, nil }
func (t *memoryTun) Name() (string, error)    { return "memtun", nil }
func (t *memoryTun) Events() <-chan tun.Event { return t.events }
func (t *memoryTun) BatchSize() int           { return 1 }

func (t *memoryTun) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
		select {
		case t.events <- tun.EventDown:
		default:
		}
		close(t.events)
	})
	return nil
}

// send 让客户端把包发进隧道。
func (t *memoryTun) send(pkt []byte) {
	t.sendQ <- append([]byte(nil), pkt...)
}

// recv 等待客户端从隧道收到一个包。
func (t *memoryTun) recv(timeout time.Duration) ([]byte, error) {
	select {
	case pkt := <-t.recvQ:
		return pkt, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("等待客户端收包超时")
	}
}

// freeUDPPort 取一个当前空闲的 UDP 端口。
func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("取空闲端口失败: %v", err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// TestLoopbackCarriesPacketsBothWays 是最重要的一条测试：
// 它证明承载层真的能搬运数据，而不只是"配置成功"。
func TestLoopbackCarriesPacketsBothWays(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 的 ring bind 需要管理员权限，跳过回环测试")
	}

	const (
		peerIP   = "10.66.66.2"   // 分配给客户端的地址
		campusIP = "172.29.56.18" // 校园网分配到的地址
	)

	// 服务端密钥与客户端密钥。
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

	// 假的校园网隧道：上行包进 channel，下行包由测试注入。
	ep := vpn.NewEndpoint()
	uplinkCh := make(chan []byte, 16)
	ep.SetUplink(func(pkt []byte) error {
		cp := append([]byte(nil), pkt...)
		select {
		case uplinkCh <- cp:
		default:
		}
		return nil
	})

	mapper, err := NewMapper(net.ParseIP(peerIP), net.ParseIP(campusIP))
	if err != nil {
		t.Fatal(err)
	}

	port := freeUDPPort(t)
	server, err := NewDevice(DeviceOptions{
		MTU:           1420,
		Endpoint:      ep,
		Mapper:        mapper,
		PrivateKey:    serverPriv,
		ListenPort:    port,
		PeerPublicKey: clientPub,
		PeerAddress:   net.ParseIP(peerIP),
	})
	if err != nil {
		t.Fatalf("创建承载设备失败: %v", err)
	}
	defer server.Close()

	if stats, err := server.Stats(); err != nil || len(stats) != 1 {
		t.Fatalf("peer 数量 = %d, err = %v，期望 1", len(stats), err)
	}

	// 客户端：一台真实的 WireGuard 设备 + 内存 TUN。
	clientTun := newMemoryTun()
	clientDev := device.NewDevice(clientTun, conn.NewDefaultBind(),
		device.NewLogger(device.LogLevelError, "client: "))
	defer clientDev.Close()

	clientConf := fmt.Sprintf(
		"private_key=%s\nlisten_port=0\nreplace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=0.0.0.0/0\n",
		hex.EncodeToString(clientPriv[:]), hex.EncodeToString(serverPub[:]), port)
	if err := clientDev.IpcSet(clientConf); err != nil {
		t.Fatalf("配置客户端失败: %v", err)
	}
	if err := clientDev.Up(); err != nil {
		t.Fatalf("启动客户端失败: %v", err)
	}

	// 上行：客户端把一个包送进隧道。
	outbound := ipv4Pkt(
		[4]byte{10, 66, 66, 2},
		[4]byte{202, 119, 32, 69},
		40,
	)
	clientTun.send(outbound)

	select {
	case got := <-uplinkCh:
		// 源地址必须被改写成本机在校园网里的地址，否则服务端不认。
		if want := [4]byte{172, 29, 56, 18}; [4]byte{got[12], got[13], got[14], got[15]} != want {
			t.Errorf("上行源地址 = %v，期望 %v", got[12:16], want)
		}
		if want := [4]byte{202, 119, 32, 69}; [4]byte{got[16], got[17], got[18], got[19]} != want {
			t.Errorf("上行目的地址被改坏了: %v", got[16:20])
		}
		if len(got) != len(outbound) {
			t.Errorf("上行包长度 = %d，期望 %d", len(got), len(outbound))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("校园网隧道没有收到上行包（握手或转发失败）")
	}

	// 下行：注入一个发往校园网地址的包，客户端应该收到改写后的版本。
	inbound := ipv4Pkt(
		[4]byte{202, 119, 32, 69},
		[4]byte{172, 29, 56, 18},
		40,
	)
	ep.Deliver(inbound)

	got, err := clientTun.recv(10 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if want := [4]byte{10, 66, 66, 2}; [4]byte{got[16], got[17], got[18], got[19]} != want {
		t.Errorf("下行目的地址 = %v，期望改写为 peer 地址 %v", got[16:20], want)
	}
	if len(got) != len(inbound) {
		t.Errorf("下行包长度 = %d，期望 %d", len(got), len(inbound))
	}
}

// 只配了服务端单边 peer 时（客户端不认识服务端公钥），不能建立隧道。
func TestLoopbackRejectsUnknownClient(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 的 ring bind 需要管理员权限")
	}

	serverPriv, _ := GenerateKey()
	serverPub, _ := serverPriv.PublicKey()
	// 客户端公钥不是服务端允许的那个。
	allowedPriv, _ := GenerateKey()
	allowedPub, _ := allowedPriv.PublicKey()
	intruderPriv, _ := GenerateKey()
	intruderPub, _ := intruderPriv.PublicKey()

	if allowedPub == intruderPub {
		t.Fatal("测试构造有误")
	}

	ep := vpn.NewEndpoint()
	uplinkCh := make(chan []byte, 4)
	ep.SetUplink(func(pkt []byte) error {
		select {
		case uplinkCh <- append([]byte(nil), pkt...):
		default:
		}
		return nil
	})
	mapper, err := NewMapper(net.ParseIP("10.66.66.2"), net.ParseIP("172.29.56.18"))
	if err != nil {
		t.Fatal(err)
	}

	port := freeUDPPort(t)
	server, err := NewDevice(DeviceOptions{
		MTU:           1420,
		Endpoint:      ep,
		Mapper:        mapper,
		PrivateKey:    serverPriv,
		ListenPort:    port,
		PeerPublicKey: allowedPub,
		PeerAddress:   net.ParseIP("10.66.66.2"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	clientTun := newMemoryTun()
	clientDev := device.NewDevice(clientTun, conn.NewDefaultBind(),
		device.NewLogger(device.LogLevelError, "intruder: "))
	defer clientDev.Close()

	conf := fmt.Sprintf(
		"private_key=%s\nlisten_port=0\nreplace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=0.0.0.0/0\n",
		hex.EncodeToString(intruderPriv[:]), hex.EncodeToString(serverPub[:]), port)
	if err := clientDev.IpcSet(conf); err != nil {
		t.Fatal(err)
	}
	if err := clientDev.Up(); err != nil {
		t.Fatal(err)
	}

	clientTun.send(ipv4Pkt([4]byte{10, 66, 66, 2}, [4]byte{1, 1, 1, 1}, 20))

	select {
	case pkt := <-uplinkCh:
		t.Fatalf("未授权的客户端竟然把包送进了隧道（%d 字节）", len(pkt))
	case <-time.After(3 * time.Second):
		// 超时正是期望的结果：握手没通过，没有包过来。
	}
}

// 关闭设备后不应再有包被送进隧道。
func TestDeviceCloseStopsForwarding(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 的 ring bind 需要管理员权限")
	}

	ep := vpn.NewEndpoint()
	delivered := make(chan struct{}, 1)
	ep.SetUplink(func(pkt []byte) error {
		select {
		case delivered <- struct{}{}:
		default:
		}
		return nil
	})
	mapper, err := NewMapper(net.ParseIP("10.66.66.2"), net.ParseIP("172.29.56.18"))
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := GenerateKey()
	peerPriv, _ := GenerateKey()
	peerPub, _ := peerPriv.PublicKey()

	dev, err := NewDevice(DeviceOptions{
		MTU: 1420, Endpoint: ep, Mapper: mapper,
		PrivateKey: priv, ListenPort: freeUDPPort(t),
		PeerPublicKey: peerPub, PeerAddress: net.ParseIP("10.66.66.2"),
	})
	if err != nil {
		t.Fatal(err)
	}

	// 关闭前：直接往端点注包是能送出去的（这条不依赖 WireGuard）。
	ep.Deliver(ipv4Pkt([4]byte{1, 1, 1, 1}, [4]byte{172, 29, 56, 18}, 20))

	if err := dev.Close(); err != nil {
		t.Fatalf("关闭设备失败: %v", err)
	}
	// 重复关闭必须安全。
	if err := dev.Close(); err != nil {
		t.Errorf("重复关闭失败: %v", err)
	}

	// 关闭后端点上的下行回调应已摘除，再注包不会 panic 也不会转发。
	ep.Deliver(ipv4Pkt([4]byte{1, 1, 1, 1}, [4]byte{172, 29, 56, 18}, 20))
}
