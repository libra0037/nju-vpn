package config

import (
	"os"
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

// 写回设备标识时不能把文件里的注释冲掉，也不能改权限——
// 那份文件是给人看的，用 YAML 序列化重写会全部丢注释。
func TestPersistDeviceIDKeepsCommentsAndMode(t *testing.T) {
	body := "# 我的配置\nserver: vpn.example.edu\nusername: u\n"
	path := writeConfig(t, body, 0o600)

	if err := PersistDeviceID(path, "new-id"); err != nil {
		t.Fatalf("写回失败: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "device_id: new-id") {
		t.Errorf("没有写入设备标识:\n%s", got)
	}
	if !strings.Contains(string(got), "# 我的配置") {
		t.Errorf("原有注释被冲掉了:\n%s", got)
	}
	if cfg, err := Load(path); err != nil || cfg.DeviceID != "new-id" {
		t.Errorf("写回后应能加载到新标识: %v / %v", cfg, err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("文件权限 = %04o，期望 0600", fi.Mode().Perm())
	}
}

// 配置文件里本来没有 device_id 时追加一行。
func TestPersistDeviceIDAppendsWhenMissing(t *testing.T) {
	path := writeConfig(t, "server: vpn.example.edu\nusername: u\n", 0o600)
	if err := PersistDeviceID(path, "first-id"); err != nil {
		t.Fatalf("写回失败: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("写回后应仍可加载: %v", err)
	}
	if cfg.DeviceID != "first-id" {
		t.Errorf("device_id = %q，期望 first-id", cfg.DeviceID)
	}
}

// 已经有值时不覆盖：两个进程同时首启同一份配置时，先写的那份才算数。
func TestPersistDeviceIDKeepsExistingValue(t *testing.T) {
	path := writeConfig(t, validConfig+"device_id: keepme\n", 0o600)
	if err := PersistDeviceID(path, "other"); err != nil {
		t.Fatalf("写回失败: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DeviceID != "keepme" {
		t.Errorf("device_id = %q，期望 keepme", cfg.DeviceID)
	}
}
