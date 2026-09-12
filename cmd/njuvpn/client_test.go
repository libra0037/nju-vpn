package main

import (
	"bufio"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/libra0037/nju-vpn/internal/config"
	"github.com/libra0037/nju-vpn/internal/ipc"
)

// TestEnsureProbeIsSafe 验证本机隧道在跑时会拦住 probe。
//
// probe 会完整登录一次，占掉该账号唯一的会话名额：正在跑的隧道会被踢下线，
// 短信模式下还要再花一条验证码。
func TestEnsureProbeIsSafe(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	cfg := &config.Config{}
	cfg.SetSourcePath(configPath)
	cfg.IPC.Endpoint = ipc.EndpointFor(configPath)

	// 服务进程没在跑时不该拦。
	if err := ensureProbeIsSafe(cfg); err != nil {
		t.Fatalf("服务进程没在跑时不该拦: %v", err)
	}

	ln, err := ipc.Listen(cfg.IPC.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if _, err := ipc.ReadRequest(bufio.NewReader(c)); err != nil {
					return
				}
				_ = ipc.WriteResponse(c, ipc.Response{Code: ipc.CodeOK, Message: "up | 校园网地址 172.29.56.18"})
			}(conn)
		}
	}()

	err = ensureProbeIsSafe(cfg)
	if err == nil {
		t.Fatal("隧道在跑时应当拦住 probe")
	}
	if !strings.Contains(err.Error(), "-force") {
		t.Fatalf("提示里要给出路（-force），实际 %v", err)
	}
}

// TestPrecheckListenPort 验证端口预检：占用的端口要在登录之前报错。
//
// 这条检查的价值在于失败得早：真等到承载层启动才报错，登录、短信、
// query-ip 都已经走完，白烧一次建隧道配额。
func TestPrecheckListenPort(t *testing.T) {
	busy, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	busyPort := busy.LocalAddr().(*net.UDPAddr).Port

	if err := precheckListenPort(&config.Config{WireGuard: config.WireGuard{ListenPort: busyPort}}); err == nil {
		t.Fatal("端口被占用时应当报错")
	}
	if err := precheckListenPort(&config.Config{WireGuard: config.WireGuard{ListenPort: busyPort + 1}}); err != nil {
		t.Fatalf("空闲端口不该报错: %v", err)
	}
	if err := precheckListenPort(&config.Config{WireGuard: config.WireGuard{ListenPort: busyPort, ListenHost: "bogus"}}); err == nil {
		t.Fatal("listen_host 写错时应当报错")
	}
}

// TestEndpointOfPrefersExplicitEndpoint 验证显式配置的端点优先。
func TestEndpointOfPrefersExplicitEndpoint(t *testing.T) {
	cfg := &config.Config{IPC: config.IPC{Endpoint: "/tmp/custom.sock"}}
	cfg.SetSourcePath("/tmp/config.yaml")

	if got, want := endpointOf(cfg), "/tmp/custom.sock"; got != want {
		t.Fatalf("endpointOf = %q, want %q", got, want)
	}
}

// TestEndpointOfDerivesFromConfigPath 验证没写 ipc.endpoint 时按配置路径派生。
func TestEndpointOfDerivesFromConfigPath(t *testing.T) {
	cfg := &config.Config{}
	cfg.SetSourcePath("/tmp/instance-a.yaml")

	if got, want := endpointOf(cfg), ipc.EndpointFor("/tmp/instance-a.yaml"); got != want {
		t.Fatalf("endpointOf = %q, want %q", got, want)
	}
	other := &config.Config{}
	other.SetSourcePath("/tmp/instance-b.yaml")
	if endpointOf(cfg) == endpointOf(other) {
		t.Fatal("两份不同的配置派生出同一个端点，命令会打到别的实例上")
	}
}

// TestEndpointForMissingConfigIsFatal 验证显式给的 -config 读不出来时报错。
//
// 回落默认端点会让 stop / restart 打到另一个实例上，那比"命令用不了"糟。
func TestEndpointForMissingConfigIsFatal(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.yaml")

	if _, err := endpointFor(missing); err == nil {
		t.Fatal("显式指定的配置不存在时应报错")
	}
}

// TestEndpointForDefaultConfigPathFallback 验证没指定 -config 时按默认路径派生。
//
// 默认路径上的配置可能还没写、或者因为别的原因读不出来，此时端点仍然由
// 路径决定，命令会以"服务进程是否在运行"收场，而不是连到别的实例上。
func TestEndpointForDefaultConfigPathFallback(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	got, err := endpointFor("")
	if err != nil {
		t.Fatalf("默认路径下的配置读不出来时不应报错: %v", err)
	}
	if want := ipc.EndpointFor(config.DefaultPath()); got != want {
		t.Fatalf("endpointFor = %q, want %q", got, want)
	}
}
