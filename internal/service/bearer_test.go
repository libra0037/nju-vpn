package service

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/config"
	"github.com/libra0037/nju-vpn/internal/wireguard"
)

// TestNewFailsOnBadKeys 验证承载设备的构造过程就是校验过程。
//
// 以前密钥是在隧道握手之后才解析的：用户等完短信、输完验证码、占掉一次
// 建隧道配额，才拿到「private_key 不是合法 base64」。现在设备在服务进程
// 启动时建，这类错误当场暴露，一条短信都不会烧。
func TestNewFailsOnBadKeys(t *testing.T) {
	t.Run("私钥不是合法 base64", func(t *testing.T) {
		_, err := New(baseConfig(t, func(cfg *config.Config) {
			cfg.WireGuard.PrivateKey = "这不是密钥"
		}))
		if err == nil || !strings.Contains(err.Error(), "private_key") {
			t.Fatalf("应报私钥错误，实际 %v", err)
		}
	})

	t.Run("缺少私钥", func(t *testing.T) {
		_, err := New(baseConfig(t, func(cfg *config.Config) {
			cfg.WireGuard.PrivateKey = ""
		}))
		if err == nil {
			t.Fatal("缺少私钥时应当报错")
		}
	})

	t.Run("接入公钥不是合法 base64", func(t *testing.T) {
		_, err := New(baseConfig(t, func(cfg *config.Config) {
			cfg.WireGuard.PeerPublicKey = "坏公钥"
		}))
		if err == nil || !strings.Contains(err.Error(), "peer_public_key") {
			t.Fatalf("应报接入公钥错误，实际 %v", err)
		}
	})

	t.Run("peer 地址不是 IPv4", func(t *testing.T) {
		_, err := New(baseConfig(t, func(cfg *config.Config) {
			cfg.WireGuard.PeerAddress = "2001:db8::2"
		}))
		if err == nil {
			t.Fatal("peer 地址不是 IPv4 时应当报错")
		}
	})
}

// TestNewBindsListenPort 验证端口在启动时就被占住：冲突当场报错。
//
// 以前要等到登录、短信、query-ip 全部走完才绑端口（R1），白烧一次配额。
func TestNewBindsListenPort(t *testing.T) {
	busy, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	port := busy.LocalAddr().(*net.UDPAddr).Port

	_, err = New(baseConfig(t, func(cfg *config.Config) {
		cfg.WireGuard.ListenPort = port
	}))
	if err == nil {
		t.Fatal("端口被占用时应当报错")
	}
	if !strings.Contains(err.Error(), "承载") {
		t.Fatalf("错误里应点名承载层，实际 %v", err)
	}
}

// TestDeviceOutlivesSession 验证承载设备跨会话存活，peer 随会话挂上摘掉。
//
// 这是这次改造的核心不变量：设备在进程启动时建好（端口占住、私钥校验），
// 一次登录只换来"挂上一个 peer"。断开时必须把 peer 摘掉——否则客户端
// 握手成功却发不出任何包，"连上了但什么都打不开"比连不上更难查。
func TestDeviceOutlivesSession(t *testing.T) {
	peerKey := testPublicKey(t)
	h := newHarnessWith(t, func(cfg *config.Config) {
		cfg.WireGuard.PeerPublicKey = peerKey
	})

	// 启动后、建立隧道之前：设备在监听，但没有任何 peer。
	if stats, err := h.svc.dev.Stats(); err != nil || len(stats) != 0 {
		t.Fatalf("隧道没建之前不该有 peer，实际 %d 个，err = %v", len(stats), err)
	}
	portBefore, err := h.svc.dev.ListenPort()
	if err != nil {
		t.Fatalf("读取端口失败: %v", err)
	}

	if err := h.svc.StartWithPassword("p"); err != nil {
		t.Fatalf("建立隧道失败: %v", err)
	}
	waitState(t, h.svc, StateUp, 3*time.Second)
	if stats, err := h.svc.dev.Stats(); err != nil || len(stats) != 1 {
		t.Fatalf("隧道建立后应有 1 个 peer，实际 %d 个，err = %v", len(stats), err)
	}

	if err := h.svc.Stop(); err != nil {
		t.Fatalf("断开失败: %v", err)
	}
	if stats, err := h.svc.dev.Stats(); err != nil || len(stats) != 0 {
		t.Fatalf("断开后应摘掉 peer，实际 %d 个，err = %v", len(stats), err)
	}

	// 设备本身还在：同一个端口仍然被占着，下次 start 不必重建。
	portAfter, err := h.svc.dev.ListenPort()
	if err != nil {
		t.Fatalf("断开后读取端口失败: %v", err)
	}
	if portAfter != portBefore {
		t.Fatalf("设备被重建了：端口 %d -> %d", portBefore, portAfter)
	}
}

// TestSetPeerWhileIdleIsDeferred 验证空闲时改公钥不会挂到设备上。
//
// 空闲时设备仍在监听：装了 peer 会让客户端握手成功、随后每个包都被丢弃。
func TestSetPeerWhileIdleIsDeferred(t *testing.T) {
	h := newHarnessWith(t, func(cfg *config.Config) { cfg.WireGuard.PeerPublicKey = "" })
	if err := h.svc.SetPeer(testPublicKey(t)); err != nil {
		t.Fatalf("记录公钥失败: %v", err)
	}
	if h.svc.peerKey.IsZero() {
		t.Fatal("公钥应记在服务对象里，供下次建立隧道时使用")
	}
	if stats, err := h.svc.dev.Stats(); err != nil || len(stats) != 0 {
		t.Fatalf("空闲时不该把 peer 挂到设备上，实际 %d 个，err = %v", len(stats), err)
	}
}

// baseConfig 造一份能通过校验、但未必能起设备的配置。
func baseConfig(t *testing.T, mutate func(*config.Config)) *config.Config {
	t.Helper()
	cfg := &config.Config{
		Server:   "vpn.example.edu",
		Port:     443,
		Username: "u",
		Password: "p",
		MTU:      1320,
		WireGuard: config.WireGuard{
			PeerAddress: "10.66.66.2",
			PrivateKey:  testPrivateKey(t),
		},
	}
	if mutate != nil {
		mutate(cfg)
	}
	return cfg
}

// testPublicKey 生成一个测试用的公钥。
func testPublicKey(t *testing.T) string {
	t.Helper()
	key, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return pub.String()
}
