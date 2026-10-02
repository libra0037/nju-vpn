package config

import (
	"strings"
	"testing"
)

// 设备标识要长期留在配置里：它决定授信终端绑的是哪台设备，写丢了就得重新
// 做一次二次验证。
func TestLoadReadsDeviceIDAndLoginDomain(t *testing.T) {
	path := writeConfig(t, validConfig+"device_id: abc123\nlogin_domain: staff\n", 0o600)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if cfg.DeviceID != "abc123" {
		t.Errorf("device_id = %q，期望 abc123", cfg.DeviceID)
	}
	if cfg.LoginDomain != "staff" {
		t.Errorf("login_domain = %q，期望 staff", cfg.LoginDomain)
	}
	if cfg.ConnectAddr() != "vpn.example.edu:443" {
		t.Errorf("没有 server_ip 时应回落到 server:port，得到 %q", cfg.ConnectAddr())
	}
}

func TestConnectAddrPrefersServerIP(t *testing.T) {
	path := writeConfig(t, validConfig+"server_ip: 203.0.113.7\n", 0o600)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if got := cfg.ConnectAddr(); got != "203.0.113.7:443" {
		t.Errorf("ConnectAddr = %q，期望 203.0.113.7:443", got)
	}
}

// 设备标识为空时只提示，不拒绝启动——首次启动就是要靠这一步生成它。
func TestWarningsMentionMissingDeviceID(t *testing.T) {
	cfg, err := Load(writeConfig(t, validConfig, 0o600))
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	joined := strings.Join(cfg.Warnings(), " | ")
	if !strings.Contains(joined, "device_id") {
		t.Errorf("警告里应提到 device_id，得到 %q", joined)
	}
}
