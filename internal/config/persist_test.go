package config

import (
	"os"
	"strings"
	"testing"
)

// TestPersistPrivateKeyKeepsExistingValue 验证已有私钥不会被覆盖。
//
// 两个进程同时首启同一份配置时，两边都会生成私钥并写回；后写的那个
// 会让盘上的私钥与正在运行的进程内存里的不一致，客户端配置随之全部失效。
func TestPersistPrivateKeyKeepsExistingValue(t *testing.T) {
	path := writeConfig(t, "server: vpn.example.edu\nusername: u\nwireguard:\n  private_key: keepme\n", 0o600)

	if err := PersistPrivateKey(path, "newkey"); err != nil {
		t.Fatalf("写回失败: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "keepme") {
		t.Fatalf("已有的私钥被覆盖了:\n%s", body)
	}
}

// 回归：私钥要写回配置文件，而且不能把文件里的注释冲掉——
// 那份文件是给人看的，用 YAML 序列化会全部丢注释。
func TestPersistPrivateKeyReplacesExistingLine(t *testing.T) {
	body := "# njuvpn 配置\n" +
		"server: vpn.example.edu\n" +
		"username: u\n" +
		"password: p\n" +
		"\n" +
		"# --- WireGuard 承载 ---\n" +
		"wireguard:\n" +
		"  listen_port: 51820        # 对外暴露的 UDP 端口\n" +
		"  private_key: \"\"           # 留空则首次启动自动生成\n" +
		"  peer_address: 10.66.66.2\n"
	path := writeConfig(t, body, 0o600)
	const key = "cHJpdmF0ZSBrZXkgcGxhY2Vob2xkZXIgYnl0ZXMgIQ=="

	if err := PersistPrivateKey(path, key); err != nil {
		t.Fatalf("写回失败: %v", err)
	}

	raw := readFile(t, path)
	if !strings.Contains(raw, "private_key: "+key) {
		t.Errorf("私钥没有写进配置: %s", raw)
	}
	if strings.Count(raw, "private_key:") != 1 {
		t.Errorf("private_key 出现了多次: %s", raw)
	}
	// 注释与同段里的其它字段必须原样保留。
	wants := []string{
		"# njuvpn 配置",
		"# 对外暴露的 UDP 端口",
		// 被改写的那一行自己的行尾注释也不能丢。
		"# 留空则首次启动自动生成",
		"listen_port: 51820",
		"peer_address: 10.66.66.2",
	}
	for _, want := range wants {
		if !strings.Contains(raw, want) {
			t.Errorf("注释或字段丢失: %q，实际内容: %s", want, raw)
		}
	}
	// 权限不能被放宽：文件里有账号口令。
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("权限变成了 %04o", fi.Mode().Perm())
	}
}

// wireguard 段存在但没有 private_key 行时，插到段内。
func TestPersistPrivateKeyInsertsIntoExistingSection(t *testing.T) {
	body := "server: vpn.example.edu\n" +
		"username: u\n" +
		"password: p\n" +
		"wireguard:\n" +
		"  listen_port: 51820\n" +
		"\n" +
		"log:\n" +
		"  level: info\n"
	path := writeConfig(t, body, 0o600)
	const key = "a2V5"

	if err := PersistPrivateKey(path, key); err != nil {
		t.Fatal(err)
	}
	raw := readFile(t, path)
	if !strings.Contains(raw, "  private_key: "+key) {
		t.Errorf("没有插入 private_key: %s", raw)
	}
	// 必须插在 wireguard 段里，不能落到 log 段之后。
	if strings.Index(raw, "private_key") > strings.Index(raw, "log:") {
		t.Errorf("插错了位置: %s", raw)
	}
}

// 完全没有 wireguard 段时追加一段，并且结果仍可被解析。
func TestPersistPrivateKeyAppendsSection(t *testing.T) {
	body := "server: vpn.example.edu\nusername: u\npassword: p\n"
	path := writeConfig(t, body, 0o600)
	const key = "a2V5"

	if err := PersistPrivateKey(path, key); err != nil {
		t.Fatal(err)
	}
	raw := readFile(t, path)
	if !strings.Contains(raw, "wireguard:") || !strings.Contains(raw, "  private_key: "+key) {
		t.Errorf("没有追加 wireguard 段: %s", raw)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("写回后配置无法解析: %v", err)
	}
	if cfg.WireGuard.PrivateKey != key {
		t.Errorf("解析出的私钥 = %q", cfg.WireGuard.PrivateKey)
	}
}

// 写回的私钥必须能被 Load 读回来，形成闭环。
func TestPersistPrivateKeyRoundTrip(t *testing.T) {
	path := writeConfig(t, validConfig, 0o600)
	const key = "cm91bmQgdHJpcCBrZXkgYnl0ZXMh"

	if err := PersistPrivateKey(path, key); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WireGuard.PrivateKey != key {
		t.Errorf("读回的私钥 = %q，期望 %q", cfg.WireGuard.PrivateKey, key)
	}
	if cfg.SourcePath() != path {
		t.Errorf("SourcePath = %q，期望 %q", cfg.SourcePath(), path)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
