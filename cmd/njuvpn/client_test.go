package main

import (
	"path/filepath"
	"testing"

	"github.com/libra0037/nju-vpn/internal/config"
	"github.com/libra0037/nju-vpn/internal/ipc"
)

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
