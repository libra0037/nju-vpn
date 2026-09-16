package main

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/libra0037/nju-vpn/internal/config"
	"github.com/libra0037/nju-vpn/internal/ipc"
	"golang.org/x/term"
)

// fakeStateService 起一个只回答 state 命令的假服务端。
//
// 返回的 set 用来安排它下一次回报的状态。
func fakeStateService(t *testing.T) (endpoint string, set func(string)) {
	t.Helper()
	endpoint = filepath.Join(t.TempDir(), "njuvpn.sock")
	ln, err := ipc.Listen(endpoint)
	if err != nil {
		t.Fatalf("监听假服务端: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	state := make(chan string, 8)
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
				_ = ipc.WriteResponse(c, ipc.Response{Code: ipc.CodeOK, Message: <-state})
			}(conn)
		}
	}()
	return endpoint, func(s string) { state <- s }
}

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

	// 假服务端按 state 命令如实回报状态（不再回那句给人看的文本：
	// 按文本切出来的状态曾经让这个闸静默失效）。
	endpoint, setState := fakeStateService(t)
	cfg.IPC.Endpoint = endpoint

	// 只有"本机没有会话"的状态才放行。
	for _, st := range []string{"idle", "error"} {
		setState(st)
		if err := ensureProbeIsSafe(cfg); err != nil {
			t.Errorf("状态 %s 时不该拦: %v", st, err)
		}
	}
	// 登录中与建承载中也持有会话（都会完整登录一次），必须拦住。
	for _, st := range []string{"up", "auth_pending", "logging_in", "connecting"} {
		setState(st)
		err := ensureProbeIsSafe(cfg)
		if err == nil {
			t.Fatalf("状态 %s 时应当拦住 probe", st)
		}
		if !strings.Contains(err.Error(), "-force") {
			t.Fatalf("提示里要给出路（-force），实际 %v", err)
		}
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

// 回归：隧道已经在跑时，start 不该再问口令。
//
// 看门狗式脚本每隔几分钟敲一次 start，而 stdin 往往是 /dev/null：
// 旧实现每次都停在口令提示上，以一句裸 EOF 收场（退出码 1），
// 连"已经在跑、幂等返回 0"这条路径都到不了。
func TestPasswordForSkipsPromptWhenTunnelUp(t *testing.T) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		t.Skip("stdin 是终端时，无法区分'没有提问'与'提问后被回答'")
	}
	endpoint, setState := fakeStateService(t)
	setState("up")

	cfg := &config.Config{} // 配置里没写口令
	password, err := passwordFor(cfg, endpoint)
	if err != nil {
		t.Fatalf("隧道已经在跑时不该因为读不到口令而失败: %v", err)
	}
	if password != "" {
		t.Fatalf("不该有口令被读进来，实际 %q", password)
	}
}

// 回归：非交互场景下读不到口令时，要给一句能照做的话。
func TestPasswordForExplainsEndOfInput(t *testing.T) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		t.Skip("stdin 是终端时不会读到文件结束")
	}
	endpoint, setState := fakeStateService(t)
	setState("idle") // 没有隧道，于是会去提示输入口令

	_, err := passwordFor(&config.Config{}, endpoint)
	if err == nil {
		t.Fatal("读不到口令时应当报错")
	}
	if !strings.Contains(err.Error(), "password") {
		t.Fatalf("错误里要告诉用户怎么办（把口令写进配置），实际 %v", err)
	}
}

// 回归：服务进程在跑、但答不出状态时，probe 也要拦住。
//
// 两端混用版本（命令行是新的、服务进程还是旧的）时 state 命令不被认识，
// 这时"有没有会话"问不出来——放行的代价是踢掉正在跑的隧道，拦一下只是
// 让用户加个 -force。
func TestEnsureProbeIsSafeBlocksOnUnknownState(t *testing.T) {
	endpoint := filepath.Join(t.TempDir(), "njuvpn.sock")
	ln, err := ipc.Listen(endpoint)
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
				_ = ipc.WriteResponse(c, ipc.Response{
					Code: ipc.CodeBadRequest, Message: "未知命令: state",
				})
			}(conn)
		}
	}()

	cfg := &config.Config{}
	cfg.IPC.Endpoint = endpoint
	err = ensureProbeIsSafe(cfg)
	if err == nil {
		t.Fatal("问不出状态时应当拦住 probe")
	}
	if !strings.Contains(err.Error(), "-force") {
		t.Fatalf("提示里要给出路（-force），实际 %v", err)
	}
}
