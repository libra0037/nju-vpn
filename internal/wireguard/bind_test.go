package wireguard

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// 这两个用例用"能不能在同一个端口的另一个地址上再绑一次"来判定监听范围，
// 比发包探测可靠：绑到 0.0.0.0 时，再绑具体地址会得到 EADDRINUSE；
// 只绑 127.0.0.1 时，绑其他本机地址仍然成功。

// 回归：默认只监听回环。同一个局域网里的其他人不该能打到这个 UDP 端口。
func TestLoopbackBindOnlyClaimsLoopbackAddress(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 走 ring bind，行为不同")
	}
	external := externalIPv4(t)
	if external == "" {
		t.Skip("本机没有非回环 IPv4 地址")
	}

	bind := &loopbackBind{}
	_, port, err := bind.Open(0)
	if err != nil {
		t.Fatalf("打开绑定失败: %v", err)
	}
	defer bind.Close()

	// 回环上已经绑住了：同地址同端口再绑必须失败。
	if _, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)}); err == nil {
		t.Error("回环地址上的端口没有被占住")
	}

	// 非回环地址上没被占：还能绑成功，说明没有监听全部网卡。
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(external), Port: int(port)})
	if err != nil {
		t.Fatalf("端口 %d 在 %s 上已被占用，说明绑定到了全部网卡: %v", port, external, err)
	}
	probe.Close()
}

// 配置成 all 时，端口应当占据全部网卡。
func TestListenAllClaimsEveryAddress(t *testing.T) {
	external := externalIPv4(t)
	if external == "" {
		t.Skip("本机没有非回环 IPv4 地址")
	}

	bind := newBind(ListenAll)
	_, port, err := bind.Open(0)
	if err != nil {
		t.Fatalf("打开绑定失败: %v", err)
	}
	defer bind.Close()

	if _, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(external), Port: int(port)}); err == nil {
		t.Errorf("配置为 all 时 %s:%d 仍可被抢占，说明没有监听全部网卡", external, port)
	}
}

// 绑定层自身的基本行为：收发、解析端点、关闭后报错。
func TestLoopbackBindRoundTrip(t *testing.T) {
	server := &loopbackBind{}
	fns, port, err := server.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if len(fns) != 1 {
		t.Fatalf("接收函数数量 = %d，期望 1", len(fns))
	}

	ep, err := server.ParseEndpoint(fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("127.0.0.1:%d", port); ep.DstToString() != want {
		t.Errorf("端点字符串 = %q，期望 %q", ep.DstToString(), want)
	}
	if len(ep.DstToBytes()) == 0 {
		t.Error("DstToBytes 为空")
	}
	if ep.DstIP().String() != "127.0.0.1" {
		t.Errorf("DstIP = %v", ep.DstIP())
	}
	if _, err := server.ParseEndpoint("not-an-endpoint"); err == nil {
		t.Error("非法端点应被拒绝")
	}

	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	payload := []byte("wireguard 承载层的测试载荷")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		bufs := [][]byte{make([]byte, 1500)}
		sizes := make([]int, 1)
		eps := make([]conn.Endpoint, 1)
		n, err := fns[0](bufs, sizes, eps)
		if err != nil {
			done <- err
			return
		}
		if n != 1 || sizes[0] != len(payload) {
			done <- fmt.Errorf("收到 %d 个包，长度 %d", n, sizes[0])
			return
		}
		if string(bufs[0][:sizes[0]]) != string(payload) {
			done <- fmt.Errorf("载荷不一致: %q", bufs[0][:sizes[0]])
			return
		}
		if eps[0] == nil {
			done <- errors.New("端点为空")
			return
		}
		// 发回去，验证 Send。
		if err := server.Send([][]byte{[]byte("收到")}, eps[0]); err != nil {
			done <- err
			return
		}
		done <- nil
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("接收失败: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("等待接收超时")
	}

	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	reply := make([]byte, 64)
	n, err := client.Read(reply)
	if err != nil {
		t.Fatalf("没收到回包: %v", err)
	}
	if string(reply[:n]) != "收到" {
		t.Errorf("回包内容 = %q", reply[:n])
	}
}

// 关闭之后接收函数必须返回 net.ErrClosed，否则设备的接收协程不会退出。
func TestLoopbackBindCloseStopsReceive(t *testing.T) {
	bind := &loopbackBind{}
	fns, _, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	if err := bind.Close(); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}

	bufs := [][]byte{make([]byte, 128)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	done := make(chan error, 1)
	go func() {
		_, err := fns[0](bufs, sizes, eps)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("关闭后接收函数应返回错误")
		}
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("错误应能被识别为 net.ErrClosed，实际 %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("关闭后接收函数没有返回")
	}

	if err := bind.Close(); err != nil {
		t.Errorf("重复关闭失败: %v", err)
	}
	if err := bind.Send([][]byte{[]byte("x")}, &conn.StdNetEndpoint{AddrPort: netip.MustParseAddrPort("127.0.0.1:1")}); err == nil {
		t.Error("关闭后发送应报错")
	}
}

// 端口变化时上游会重新 Open，旧的监听必须先释放。
func TestLoopbackBindReopenChangesPort(t *testing.T) {
	bind := &loopbackBind{}
	_, first, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := bind.Open(0)
	if err != nil {
		t.Fatalf("重新打开失败: %v", err)
	}
	defer bind.Close()

	if first == second {
		t.Errorf("重新打开后端口没有变化: %d", first)
	}
	// 旧端口必须已经释放。
	free, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(first)})
	if err != nil {
		t.Errorf("旧端口 %d 没有释放: %v", first, err)
	} else {
		free.Close()
	}
}

// 回归：设备必须真的用回环绑定，而不只是绑定层自己测着玩。
//
// 判据同样是"能不能在同一个端口的其他地址上再绑一次"：
// 设备占住了回环，就不该占住非回环地址。
func TestDeviceBindsOnlyLoopbackByDefault(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 走 ring bind，行为不同")
	}
	external := externalIPv4(t)
	if external == "" {
		t.Skip("本机没有非回环 IPv4 地址")
	}

	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	peerPriv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	peerPub, err := peerPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	port := freeUDPPort(t)
	dev, err := NewDevice(DeviceOptions{
		MTU:        1420,
		PrivateKey: priv,
		ListenPort: port,
		// ListenHost 留零值，即默认的 loopback。
	})
	if err != nil {
		t.Fatalf("创建设备失败: %v", err)
	}
	defer dev.Close()
	if err := dev.SetPeer(peerPub, net.ParseIP("10.66.66.2")); err != nil {
		t.Fatalf("配置 peer 失败: %v", err)
	}

	// 设备已经绑住了回环端口。
	if _, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}); err == nil {
		t.Error("设备没有绑住回环端口")
	}
	// 但非回环地址上仍然空着，说明没有监听全部网卡。
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(external), Port: port})
	if err != nil {
		t.Fatalf("设备占住了 %s:%d，说明监听范围不是回环: %v", external, port, err)
	}
	probe.Close()

	// 设备自己报告的端口要与请求的一致。
	got, err := dev.ListenPort()
	if err != nil {
		t.Fatal(err)
	}
	if got != port {
		t.Errorf("设备报告端口 %d，期望 %d", got, port)
	}
}

// 配置解析只接受两个明确的写法，避免拼错后静默放开监听范围。
func TestParseListenHost(t *testing.T) {
	cases := map[string]ListenHost{
		"":          ListenLoopback,
		"loopback":  ListenLoopback,
		"local":     ListenLoopback,
		"127.0.0.1": ListenLoopback,
		"all":       ListenAll,
		"any":       ListenAll,
		"0.0.0.0":   ListenAll,
	}
	for in, want := range cases {
		got, err := ParseListenHost(in)
		if err != nil {
			t.Errorf("%q 解析失败: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%q 解析为 %v，期望 %v", in, got, want)
		}
	}
	for _, bad := range []string{"everyone", "0.0.0.0/0", "true"} {
		if _, err := ParseListenHost(bad); err == nil {
			t.Errorf("%q 应被拒绝（拼错时不能静默放开监听范围）", bad)
		}
	}
}

// externalIPv4 返回本机第一个非回环 IPv4 地址。
func externalIPv4(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if v4 := ipNet.IP.To4(); v4 != nil {
				return v4.String()
			}
		}
	}
	return ""
}
