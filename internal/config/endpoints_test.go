package config

import (
	"os"
	"strings"
	"testing"
)

func TestEndpointsAreExplicitIndependentAndOldMTURejected(t *testing.T) {
	base := "server: vpn.example.edu\nusername: u\n"
	for _, wg := range []bool{false, true} {
		for _, socks := range []bool{false, true} {
			body := base
			if wg {
				body += "wireguard:\n  enabled: true\n"
			}
			if socks {
				body += "socks5:\n  enabled: true\n"
			}
			cfg, err := Load(writeConfig(t, body, 0600))
			if err != nil {
				t.Fatal(err)
			}
			if cfg.WireGuard.Enabled != wg || cfg.SOCKS5.Enabled != socks {
				t.Fatal("省略启用被推断为旧模式")
			}
			if !wg && (cfg.WireGuard.MTU != 0 || cfg.WireGuard.ListenPort != 0 || cfg.WireGuard.PeerAddress != "") {
				t.Fatal("关闭端点生成运行字段")
			}
			if socks && (cfg.SOCKS5.ListenHost != "loopback" || cfg.SOCKS5.ListenPort != 1080 || cfg.SOCKS5.MaxConnections != 128 || cfg.SOCKS5.MaxDials != 32) {
				t.Fatal("当前 SOCKS 默认值错误")
			}
		}
	}
	if _, err := Load(writeConfig(t, base+"mtu: 1400\n", 0600)); err == nil {
		t.Fatal("旧顶层 MTU 被接受")
	}
	for _, extra := range []string{"socks5:\n  enabled: true\n  listen_host: all\n", "socks5:\n  enabled: true\n  username: u\n", "socks5:\n  enabled: true\n  max_connections: 1\n  max_dials: 2\n", "socks5:\n  enabled: true\n  max_dials: 129\n", "socks5:\n  enabled: true\n  listen_port: -1\n", "socks5:\n  enabled: true\n  listen_host: invalid\n", "socks5:\n  enabled: true\n  password: true\n"} {
		if _, err := Load(writeConfig(t, base+extra, 0600)); err == nil {
			t.Fatal("非法 SOCKS 配置被接受")
		}
	}
	if _, err := Load(writeConfig(t, base+"wireguard:\n  enabled: false\n  mtu: -1\n  peer_address: missing\nsocks5:\n  enabled: true\n", 0600)); err != nil {
		t.Fatal("关闭的端点仍有运行前提", err)
	}
}

func TestSOCKSOnlyIdentityDoesNotGenerateOrPersistWireGuardKey(t *testing.T) {
	path := writeConfig(t, "server: vpn.example.edu\nusername: u\nsocks5:\n  enabled: true\n", 0600)
	cfg, err := InitializeIdentity(path, func() (string, error) { return "device-only", nil }, func() (string, error) { t.Fatal("SOCKS-only 生成了 WireGuard 密钥"); return "", nil })
	if err != nil || cfg.DeviceID != "device-only" || cfg.WireGuard.PrivateKey != "" {
		t.Fatal("共享身份初始化失败", err)
	}
	body, _ := os.ReadFile(path)
	if strings.Contains(string(body), "wireguard") || strings.Contains(string(body), "private_key") {
		t.Fatal("写回了无关身份")
	}
	if _, err := InitializeIdentity(path, func() (string, error) { t.Fatal("设备身份重新生成"); return "", nil }, func() (string, error) { t.Fatal("关闭端点生成密钥"); return "", nil }); err != nil {
		t.Fatal(err)
	}
}
