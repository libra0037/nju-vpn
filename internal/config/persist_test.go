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

// TestPersistPrivateKeyRefusesFlowSection 验证承载段写成流式时不写回。
//
// 往 "wireguard: {…}" 这样的一行后面插一行缩进两格的字段，会让整份文件解析
// 不过：进程当下照跑，下一次启动却直接以“解析配置文件失败”退出，用户只能
// 手工删改。写回方宁可失败（调用方按警告处理），也不能造出这种文件。
func TestPersistPrivateKeyRefusesFlowSection(t *testing.T) {
	original := "server: vpn.example.edu\nusername: u\nwireguard: {peer_address: 10.66.66.2, listen_port: 51820}\n"
	path := writeConfig(t, original, 0o600)

	err := PersistPrivateKey(path, "newkey")
	if err == nil {
		t.Fatal("流式写法的承载段应当拒绝写回")
	}
	if !strings.Contains(err.Error(), "块写法") {
		t.Errorf("错误应当说清是写法问题，得到 %v", err)
	}
	if got := readFile(t, path); got != original {
		t.Errorf("拒绝写回时文件必须原样不动，现在是:\n%s", got)
	}
	// 拒绝之后文件仍然可用：下一次启动还能解析。
	if _, err := Load(path); err != nil {
		t.Errorf("文件应当仍然可解析，得到 %v", err)
	}
}

// TestPersistPrivateKeyRefusesToWriteBrokenYAML 验证兜底：改动后解析不过时
// 直接不落盘，文件保持原样。
func TestPersistPrivateKeyRefusesToWriteBrokenYAML(t *testing.T) {
	original := "server: vpn.example.edu\n"
	path := writeConfig(t, original, 0o600)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	// 直接喂给写回层一份会解析失败的内容：模拟行编辑算法出错的后果。
	if err := writePreservingMode(path, fi, []string{"server: vpn.example.edu", "  bad: ["}); err == nil {
		t.Fatal("解析不过的内容应当被拒绝写回")
	}
	if got := readFile(t, path); got != original {
		t.Errorf("被拒绝时文件必须原样不动，现在是:\n%s", got)
	}
}
