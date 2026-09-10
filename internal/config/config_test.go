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
			"缺少口令",
			"server: vpn.example.edu\nusername: u\n",
			"password",
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

// 回归：配置文件里有账号口令，权限放开等于把凭据交给同机其他用户。
func TestLoadRequiresRestrictedPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 的权限模型不同")
	}
	path := writeConfig(t, validConfig, 0o644)
	_, err := Load(path)
	if err == nil {
		t.Fatal("权限过宽时必须拒绝加载")
	}
	if !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("错误信息应给出修复办法: %v", err)
	}
}

// CLI 只取端点，不该因为读不到凭据文件就失效。
func TestLoadForClientToleratesUnreadableConfig(t *testing.T) {
	cfg, err := LoadForClient(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("配置文件不存在时应返回错误，由调用方决定回退")
	}
	if cfg == nil {
		t.Fatal("即使失败也要返回可用的空配置")
	}
	if cfg.IPC.Endpoint != "" {
		t.Errorf("空配置里不该有端点: %q", cfg.IPC.Endpoint)
	}

	path := writeConfig(t, validConfig, 0o644)
	if _, err := LoadForClient(path); err == nil {
		t.Error("权限问题应当报错，由调用方决定是否继续")
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
