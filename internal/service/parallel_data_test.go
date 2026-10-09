package service

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/l3"
	"github.com/libra0037/nju-vpn/internal/wireguard"
	"github.com/libra0037/nju-vpn/internal/ztnatest"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

func TestWireGuardAndSOCKSCarryDataIndependently(t *testing.T) {
	srv := newFakeServer(t, ztnatest.Options{})
	cfg := newTestConfig(t, srv)
	cfg.SOCKS5 = socksConfig()
	peerKey, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	peerPublic, err := peerKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg.WireGuard.PeerPublicKey = peerPublic.String()
	svc := newTestService(t, srv, cfg)
	if err := svc.Start(false, ""); err != nil {
		t.Fatal(err)
	}
	serverKey, err := wireguard.ParseKey(cfg.WireGuard.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	serverPublic, err := serverKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	// 对端只搬运固定包，用同地址映射保持字节；不创建网卡或引入测试网络栈。
	endpoint := l3.New()
	endpoint.SetLocalAddr(net.ParseIP("10.1.2.3"))
	replies := make(chan []byte, 4)
	unregister := endpoint.SetUplink(func(packet []byte) error {
		replies <- append([]byte(nil), packet...)
		return nil
	})
	defer unregister()
	mapper, err := wireguard.NewDynamicMapper(net.ParseIP("10.1.2.3"), endpoint.LocalAddr4)
	if err != nil {
		t.Fatal(err)
	}
	relay := wireguard.NewRelay(wireguard.RelayOptions{MTU: 1400})
	relay.InstallSession(endpoint, mapper)
	peer := device.NewDevice(relay, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer peer.Close()
	port, err := svc.brSnapshot.Load().dev.ListenPort()
	if err != nil {
		t.Fatal(err)
	}
	conf := fmt.Sprintf("private_key=%s\nlisten_port=0\nreplace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=0.0.0.0/0\n", hex.EncodeToString(peerKey[:]), hex.EncodeToString(serverPublic[:]), port)
	if err := peer.IpcSet(conf); err != nil {
		t.Fatal(err)
	}
	if err := peer.Up(); err != nil {
		t.Fatal(err)
	}
	c, r, reply := openSOCKS(t, svc, []byte{5, 1, 0, 1, 10, 1, 2, 3, 1, 187, 'o', 'k'})
	if reply != 0 {
		t.Fatal(reply)
	}
	var echo [2]byte
	if _, err := io.ReadFull(r, echo[:]); err != nil || string(echo[:]) != "ok" {
		t.Fatal("SOCKS 数据失败", err)
	}

	for phase := 0; phase < 2; phase++ {
		if phase == 1 {
			if err := svc.StopEndpoint("socks5"); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Read(echo[:]); err == nil {
				t.Fatal("局部停止未关闭 SOCKS 流")
			}
		}
		// 固定 IPv4/UDP 上下行包分别检查校园地址和对端地址。
		packet := []byte{0x45, 0, 0, 30, 0, 1, 0, 0, 64, 17, 0, 0, 10, 66, 66, 2, 10, 1, 2, 3, 0x9c, 0x40, 1, 0xbb, 0, 10, 0, 0, 'w', 'g'}
		endpoint.Deliver(packet)
		deadline := time.Now().Add(3 * time.Second)
		for len(srv.Uplink()) < phase+1 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		packets := srv.Uplink()
		if len(packets) != phase+1 || net.IP(packets[phase][12:16]).String() != testVIP {
			t.Fatal("校园 L3 未收到独立上行")
		}
		downlink := []byte{0x45, 0, 0, 30, 0, 1, 0, 0, 64, 17, 0, 0, 10, 1, 2, 3, 172, 16, 0, 9, 1, 0xbb, 0x9c, 0x40, 0, 10, 0, 0, 'w', 'g'}
		if err := srv.SendDownlink(downlink); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-replies:
			if len(got) != 30 || net.IP(got[12:16]).String() != "10.1.2.3" || net.IP(got[16:20]).String() != "10.66.66.2" || string(got[28:]) != "wg" {
				t.Fatal("WireGuard 回包改写错误")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("WireGuard 未转发", phase)
		}
		if !svc.Status().Ready || srv.LogoutCount() != 0 {
			t.Fatal("停止 SOCKS 中断共享会话或 L3")
		}
	}
}
