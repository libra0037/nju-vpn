package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeConfig 写一份配置文件，默认给 0600 权限。
func writeConfig(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	// os.WriteFile 受 umask 影响，这里显式设一次。
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

const validConfig = `
server: vpn.example.edu
port: 443
username: u
password: p
mtu: 1320
wireguard:
  peer_address: 10.66.66.2
`

func TestLoadValidConfig(t *testing.T) {
	path := writeConfig(t, validConfig, 0o600)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("合法配置不该报错: %v", err)
	}
	if cfg.MTU != 1320 || cfg.WireGuard.PeerAddress != "10.66.66.2" {
		t.Errorf("配置解析结果异常: %+v", cfg)
	}
}

// 回归：校验只查了几个字段，MTU、端口、peer 地址写错时要等到运行时才炸，
// 而且错误信息指向完全无关的地方。
func TestLoadRejectsInvalidValues(t *testing.T) {
	// 口令不是必填项：留空表示让 `njuvpn start` 现问，经本地套接字交给
	// 服务进程，只留在内存里。这里单独钉住这个行为，避免以后又加回校验。
	t.Run("口令可以留空", func(t *testing.T) {
		path := writeConfig(t, "server: vpn.example.edu\nusername: u\n", 0o600)
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("口令留空应当合法: %v", err)
		}
		if cfg.Password != "" {
			t.Fatalf("口令应当为空，得到 %q", cfg.Password)
		}
	})

	// listen_port 写 0 表示用默认端口：applyDefaults 会把它换成 51820，
	// 所以端口预检与承载层都不会见到 0。
	t.Run("listen_port 0 回落默认端口", func(t *testing.T) {
		path := writeConfig(t, "server: vpn.example.edu\nusername: u\npassword: p\nwireguard:\n  listen_port: 0\n", 0o600)
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("listen_port 0 应当合法: %v", err)
		}
		if cfg.WireGuard.ListenPort != 51820 {
			t.Fatalf("listen_port 0 应回落 51820，得到 %d", cfg.WireGuard.ListenPort)
		}
	})

	cases := []struct {
		name string
		body string
		want string
	}{
		{
			"server 里带了端口",
			"server: vpn.example.edu:443\nusername: u\npassword: p\n",
			"带了端口",
		},
		{
			"server_ip 非法",
			"server: vpn.example.edu\nserver_ip: not-an-ip\nusername: u\npassword: p\n",
			"server_ip",
		},
		{
			"mtu 过大",
			"server: vpn.example.edu\nusername: u\npassword: p\nmtu: 1500\n",
			"mtu",
		},
		{
			"mtu 过小",
			"server: vpn.example.edu\nusername: u\npassword: p\nmtu: 100\n",
			"mtu",
		},
		{
			"监听端口越界",
			"server: vpn.example.edu\nusername: u\npassword: p\nwireguard:\n  listen_port: -1\n",
			"listen_port",
		},
		{
			"peer 地址不是 IPv4",
			"server: vpn.example.edu\nusername: u\npassword: p\nwireguard:\n  peer_address: 2001:db8::2\n",
			"peer_address",
		},
		{
			"log.level 写错",
			"server: vpn.example.edu\nusername: u\npassword: p\nlog:\n  level: warn\n",
			"log.level",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := writeConfig(t, c.body, 0o600)
			_, err := Load(path)
			if err == nil {
				t.Fatal("非法配置必须报错")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("错误信息 %q 里应提到 %q", err.Error(), c.want)
			}
		})
	}
}

// 回归：键名拼错会被静默忽略并回落默认值，用户以为配置生效了。
func TestLoadRejectsUnknownFields(t *testing.T) {
	body := "server: vpn.example.edu\nusername: u\npassword: p\nwgireguard:\n  peer_address: 10.66.66.2\n"
	path := writeConfig(t, body, 0o600)
	if _, err := Load(path); err == nil {
		t.Fatal("未知字段必须报错")
	}
}

// 回归：不再因为文件权限拒绝加载。
//
// 以前是直接拒绝，理由是"同机其他用户可以读到凭据"——但服务进程以普通用户
// 运行时，属主不同（例如 root 建的配置文件）会让它直接起不来。现在改成
// 收紧权限并提示（见 TestLoadRestrictsFilePermissions），不拒绝启动。
func TestLoadIgnoresFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 的权限模型不同")
	}
	path := writeConfig(t, validConfig, 0o644)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("不该因为权限过宽而拒绝加载: %v", err)
	}
	if cfg.Username != "u" {
		t.Errorf("配置没读全: %+v", cfg)
	}
}

// 回归：过宽的权限在加载时被收紧到 0600。
//
// 配置里有校园网口令、设备标识与 WireGuard 私钥。按文档复制一份填写
// 出来的文件是 0644；备份、打包给别人排查、镜像快照都会把它们一起带走。
func TestLoadRestrictsFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 的权限模型不同")
	}
	path := writeConfig(t, validConfig, 0o644)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("不该因为权限过宽而拒绝加载: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("权限应被收紧为 0600，实际 %04o", perm)
	}
	if warnings := strings.Join(cfg.Warnings(), "；"); !strings.Contains(warnings, "已收紧") {
		t.Fatalf("应当提示权限被收紧，实际 %v", cfg.Warnings())
	}
}

// 已经是 0600 的文件不该被碰，也不该有提示。
func TestLoadLeavesPrivatePermissionsAlone(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 的权限模型不同")
	}
	path := writeConfig(t, validConfig, 0o600)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("权限被改动了: %04o", perm)
	}
	for _, w := range cfg.Warnings() {
		if strings.Contains(w, "权限") {
			t.Fatalf("0600 的文件不该有权限提示: %q", w)
		}
	}
}

// CLI 只取端点，读不出来时要把错误如实报出来，由调用方决定回退。
func TestLoadForClientReportsUnreadableConfig(t *testing.T) {
	cfg, err := LoadForClient(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("配置文件不存在时应返回错误")
	}
	if cfg != nil {
		t.Fatal("失败时不该回一个看起来能用的空配置")
	}
}

func TestLoadForClientReadsEndpoint(t *testing.T) {
	body := validConfig + "ipc:\n  endpoint: /tmp/custom.sock\n"
	path := writeConfig(t, body, 0o600)
	cfg, err := LoadForClient(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.IPC.Endpoint; got != "/tmp/custom.sock" {
		t.Errorf("端点 = %q", got)
	}
}

// 回归：默认路径以前是坏的——Windows 分支的反斜杠全丢，njuvpn 被吃成 juvpn，
// 中间还夹了一个真实换行。参数化之后两个平台都能在这里断言。
func TestDefaultPath(t *testing.T) {
	cases := []struct {
		name string
		goos string
		env  map[string]string
		home string
		want string
	}{
		{
			"windows 用 LOCALAPPDATA", "windows",
			map[string]string{"LOCALAPPDATA": `C:\Users\x\AppData\Local`},
			`C:\Users\x`,
			`C:\Users\x\AppData\Local\njuvpn\config.yaml`,
		},
		{
			"windows 缺 LOCALAPPDATA 时退回用户目录", "windows", nil,
			`C:\Users\x`,
			`C:\Users\x\AppData\Local\njuvpn\config.yaml`,
		},
		{
			"linux 用 XDG_CONFIG_HOME", "linux",
			map[string]string{"XDG_CONFIG_HOME": "/home/x/.config"},
			"/home/x",
			"/home/x/.config/njuvpn/config.yaml",
		},
		{
			"linux 默认 ~/.config", "linux", nil,
			"/home/x",
			"/home/x/.config/njuvpn/config.yaml",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := defaultPath(c.goos, func(k string) string { return c.env[k] }, c.home)
			if got != c.want {
				t.Errorf("defaultPath = %q，想要 %q", got, c.want)
			}
			if strings.ContainsAny(got, "\n\r") {
				t.Errorf("路径里不能有换行: %q", got)
			}
		})
	}
}

// TestRedactProxyHidesPassword 验证代理地址里的口令不会经状态与日志漏出。
//
// 常态（带协议前缀）只该抹掉口令；没有协议前缀时 Go 会把 "alice:pw@host"
// 解析成 scheme=alice + opaque 主体，Redacted() 对这种形式原样返回，
// 所以必须整体换成占位符。
func TestRedactProxyHidesPassword(t *testing.T) {
	cases := []struct {
		name  string
		proxy string
	}{
		{"带协议前缀", "http://alice:s3cr3t@127.0.0.1:7897"},
		{"带协议的 socks5", "socks5://alice:s3cr3t@127.0.0.1:1080"},
		{"没有协议前缀", "alice:s3cr3t@127.0.0.1:7897"},
		{"只有协议前缀", "http://"},
		{"解析不了的端口", "http://alice:s3cr3t@127.0.0.1:79x7"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := RedactProxy(c.proxy)
			if strings.Contains(got, "s3cr3t") {
				t.Errorf("RedactProxy(%q) = %q，口令漏了出来", c.proxy, got)
			}
		})
	}

	if got := RedactProxy(""); got != "" {
		t.Errorf("空地址应当原样返回空串，得到 %q", got)
	}
	if got := RedactProxy("http://alice:s3cr3t@127.0.0.1:7897"); !strings.Contains(got, "127.0.0.1:7897") {
		t.Errorf("常态应当保留主机与端口，得到 %q", got)
	}
}

// TestParseSHA256Fingerprints 验证指纹文本的三种写法都能解析，写错时报错。
func TestParseSHA256Fingerprints(t *testing.T) {
	const colon = "21:54:05:9D:C8:84:4C:72:D8:F9:32:95:2C:D2:2E:04:9A:37:15:46:C4:E6:D1:DE:EB:5E:D1:BB:47:D1:57:54"
	plain := strings.ReplaceAll(strings.ToLower(colon), ":", "")
	if got, err := ParseSHA256Fingerprints([]string{colon, plain}); err != nil || len(got) != 2 {
		t.Fatalf("合法指纹应当解析成功，得到 %v（%d 条）", err, len(got))
	}
	if got, err := ParseSHA256Fingerprints([]string{colon, plain}); err == nil && got[0] != got[1] {
		t.Errorf("带分隔符与不带分隔符应当解析成同一个值")
	}

	for _, bad := range []string{"", "zz", "21:54", strings.Repeat("AA", 31), strings.Repeat("AA", 33)} {
		if _, err := ParseSHA256Fingerprints([]string{bad}); err == nil {
			t.Errorf("%q 不是合法指纹，应当报错", bad)
		} else if !strings.Contains(err.Error(), bad) && bad != "" {
			t.Errorf("错误里应当带上写坏的原值 %q，得到 %v", bad, err)
		}
	}
}

// TestNodePinHashesFallsBackToBuiltin 验证没有配置指纹时用内置的实测值，
// 配了就用配置的（此时 ztna 侧会按严格模式处理）。
func TestNodePinHashesFallsBackToBuiltin(t *testing.T) {
	empty := &Config{}
	got, err := empty.NodePinHashes()
	if err != nil {
		t.Fatalf("内置指纹应当可用: %v", err)
	}
	if len(got) != len(defaultPinnedNodeSHA256) {
		t.Fatalf("内置指纹条数 = %d，期望 %d", len(got), len(defaultPinnedNodeSHA256))
	}

	custom := &Config{TLS: TLS{PinnedNodeSHA256: []string{strings.Repeat("AB", 32)}}}
	got, err = custom.NodePinHashes()
	if err != nil {
		t.Fatalf("配置的指纹应当可用: %v", err)
	}
	if len(got) != 1 || got[0][0] != 0xAB {
		t.Errorf("配了指纹就不该再回退到内置值，得到 %v", got)
	}
}
