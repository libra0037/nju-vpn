package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInitializeIdentityPreservesYAMLAndAdoptsDisk(t *testing.T) {
	for _, fields := range []string{
		"device_id: null # 设备注释\nwireguard: {private_key: null, peer_address: 10.66.66.2}\n",
		"\"device_id\": '' # 设备注释\n\"wireguard\":\n  \"private_key\": '' # 私钥注释\n",
	} {
		t.Run(fields, func(t *testing.T) {
			path := writeConfig(t, "# 配置注释\nserver: vpn.example.edu\nusername: u\n"+fields, 0600)
			first, err := InitializeIdentity(path, func() (string, string, error) { return "device-a", "key-a", nil })
			if err != nil {
				t.Fatal(err)
			}
			second, err := InitializeIdentity(path, func() (string, string, error) { t.Fatal("已有身份不能再生成"); return "", "", nil })
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, cfg := range []*Config{first, second, loaded} {
				if cfg.DeviceID != "device-a" || cfg.WireGuard.PrivateKey != "key-a" {
					t.Fatal("内存未采用实际落盘身份")
				}
			}
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, comment := range []string{"# 配置注释", "# 设备注释"} {
				if !strings.Contains(string(content), comment) {
					t.Fatal("注释丢失")
				}
			}
			if runtime.GOOS != "windows" {
				info, _ := os.Stat(path)
				if info.Mode().Perm() != 0600 {
					t.Fatal("身份文件权限过宽")
				}
			}
		})
	}
}

func TestIdentityWriteDoesNotFollowPlantedTemp(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("符号链接需要特权")
	}
	path := writeConfig(t, validConfig, 0600)
	victim := filepath.Join(filepath.Dir(path), "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, fmt.Sprintf("%s.tmp.%d", path, os.Getpid())); err != nil {
		t.Fatal(err)
	}
	_, err := InitializeIdentity(path, func() (string, string, error) { return "id", "key", nil })
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(victim)
	if string(got) != "keep" {
		t.Fatal("被预置链接引导写入")
	}
}

func TestIdentityFailureDoesNotPublish(t *testing.T) {
	path := writeConfig(t, validConfig, 0600)
	before, _ := os.ReadFile(path)
	cfg, err := InitializeIdentity(path, func() (string, string, error) { return "id", "key", fmt.Errorf("entropy failed") })
	if err == nil || cfg != nil {
		t.Fatal("失败仍发布身份")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("生成失败仍写回")
	}
}

func TestLoadRejectsAmbiguousOrOversizedYAML(t *testing.T) {
	for _, extra := range []string{"\n---\nusername: replacement\n", "\na: &a [*a]\n", strings.Repeat("#", 256*1024+1)} {
		if _, err := Load(writeConfig(t, validConfig+extra, 0600)); err == nil {
			t.Fatal("无界或多文档配置被接受")
		}
	}
}

func TestConfiguredSPKIPinsOnly(t *testing.T) {
	const pin = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	for _, pins := range [][]string{nil, {}, {"short"}, {strings.Repeat("00", 32)}, {pin, pin}, {strings.TrimSuffix(pin, "=")}, {pin + "\n"}} {
		c := Config{TLS: TLS{PinnedNodeSPKISHA256: pins}}
		if _, err := c.NodeSPKIPins(); err == nil {
			t.Fatalf("非法白名单被接受: %d 项", len(pins))
		}
	}
	c := Config{TLS: TLS{PinnedNodeSPKISHA256: []string{"a2czXjambEMdvKj+wcCn2YNF4AFf84W5AXdF4GzMGAY=", "cqCxa81gLyniGGB1PyKnjhxKN2wfBTs8NNy72SfRFpY="}}}
	values, err := c.NodeSPKIPins()
	if err != nil || len(values) != 2 {
		t.Fatal(err)
	}
	values[0][0] = 0
	again, _ := c.NodeSPKIPins()
	if again[0][0] != 0x6b {
		t.Fatal("返回切片不是独立值")
	}
	for _, old := range []string{"tls:\n  pinned_node_sha256: []\n", "ipc:\n  endpoint: /tmp/custom.sock\n"} {
		if _, err := Load(writeConfig(t, validConfig+old, 0600)); err == nil {
			t.Fatal("旧字段被接受")
		}
	}
	missing := writeConfig(t, validConfig+"tls: {}\n", 0600)
	if _, err := Load(missing); err == nil {
		t.Fatal("缺失 pin 不得回退")
	}
	// 1400 是默认内层 MTU，无第二次封装扣减。
	cfg, err := Load(writeConfig(t, "server: vpn.example.edu\nusername: u\n", 0600))
	if err != nil || cfg.MTU != 1400 {
		t.Fatal("默认 MTU 应为 1400", err)
	}
}
