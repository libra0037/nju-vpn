package service

import (
	"bufio"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/config"
	"github.com/libra0037/nju-vpn/internal/ipc"
)

// TestStatusAndPingCarryInstanceIdentity 验证 status 与 ping 报出实例身份。
//
// 同机多实例同时连同一台学校服务器时，两份日志几乎逐字相同；PID、账号、
// 配置路径与端点是对上号的唯一依据，而 ping 是唯一永远可用的命令。
func TestStatusAndPingCarryInstanceIdentity(t *testing.T) {
	const configPath = "/tmp/njuvpn-identity/config.yaml"
	h := newHarnessWith(t, func(cfg *config.Config) {
		cfg.Username = "student"
		cfg.SetSourcePath(configPath)
	})
	endpoint, done := serve(t, h)

	wantEndpoint := ipc.EndpointFor(configPath)
	resp := request(t, endpoint, ipc.Request{Command: ipc.CmdStatus})
	for _, want := range []string{"pid=", "账号=student", "配置=" + configPath, "端点=" + wantEndpoint} {
		if !strings.Contains(resp.Message, want) {
			t.Errorf("status 里缺少 %q: %s", want, resp.Message)
		}
	}

	ping := request(t, endpoint, ipc.Request{Command: ipc.CmdPing})
	if !strings.HasPrefix(ping.Message, "pong ") || !strings.Contains(ping.Message, "pid=") {
		t.Errorf("ping 应报出身份，实际 %q", ping.Message)
	}

	closeServer(t, h, done)
}

// TestIdentityPrefersExplicitEndpoint 验证显式配置的端点优先于路径派生。
func TestIdentityPrefersExplicitEndpoint(t *testing.T) {
	cfg := &config.Config{Username: "u", IPC: config.IPC{Endpoint: "/tmp/explicit.sock"}}
	cfg.SetSourcePath("/tmp/ignored.yaml")

	if got := identityOf(cfg).Endpoint; got != "/tmp/explicit.sock" {
		t.Fatalf("identity 端点 = %q，想要显式配置的 /tmp/explicit.sock", got)
	}
}

// TestStatusCheckRejectsWhenNotUp 验证巡检用的 status -check 语义。
//
// 普通 status 在任何状态都返回 200（它只是查询）；带 check 时隧道不在 up
// 就以非 0 退出，脚本才不会把“进程活着”当成“链路正常”。
func TestStatusCheckRejectsWhenNotUp(t *testing.T) {
	h := newHarness(t)
	endpoint, done := serve(t, h)

	resp := request(t, endpoint, ipc.Request{Command: ipc.CmdStatus})
	if resp.Code != ipc.CodeOK {
		t.Fatalf("普通 status 应当成功，实际 %d %s", resp.Code, resp.Message)
	}
	resp = request(t, endpoint, ipc.Request{Command: ipc.CmdStatus, Args: []string{"check"}})
	if resp.Code == ipc.CodeOK {
		t.Fatalf("隧道没起来时 status -check 不该报成功: %s", resp.Message)
	}

	closeServer(t, h, done)
}

// TestStartIsIdempotent 验证隧道已经在跑时再敲一次 start 按成功处理。
//
// cron 里的看门狗最自然的写法就是定时跑一次 start；报 409 会让它一直报警。
func TestStartIsIdempotent(t *testing.T) {
	h := newHarness(t)
	endpoint, done := serve(t, h)

	if err := h.svc.StartWithPassword("p"); err != nil && !errors.Is(err, ErrAuthRequired) {
		t.Fatalf("建立隧道失败: %v", err)
	}
	waitState(t, h.svc, StateUp, 3*time.Second)

	resp := request(t, endpoint, ipc.Request{Command: ipc.CmdStart})
	if resp.Code != ipc.CodeOK {
		t.Fatalf("已经在跑时 start 应当报成功，实际 %d %s", resp.Code, resp.Message)
	}
	if !strings.Contains(resp.Message, "已在运行") {
		t.Fatalf("提示语应说明隧道本来就在跑，实际 %q", resp.Message)
	}

	closeServer(t, h, done)
}

// TestShutdownLogsOutBeforeEndpointStops 验证 restart 的前置条件。
//
// CLI 用“端点不再响应”判断旧进程已经退干净。如果先关监听、再慢慢登出，
// 新进程就会和那次登出抢同一个账号的名额（服务端只允许一条会话）。
func TestShutdownLogsOutBeforeEndpointStops(t *testing.T) {
	h := newHarness(t)
	endpoint, done := serve(t, h)

	if err := h.svc.StartWithPassword("p"); err != nil && !errors.Is(err, ErrAuthRequired) {
		t.Fatalf("建立隧道失败: %v", err)
	}
	waitState(t, h.svc, StateUp, 3*time.Second)
	if h.portal.Count("/por/logout.csp") != 0 {
		t.Fatal("还没退出就已经登出了")
	}

	resp := request(t, endpoint, ipc.Request{Command: ipc.CmdShutdown})
	if resp.Code != ipc.CodeOK {
		t.Fatalf("shutdown 应当被接受，实际 %d %s", resp.Code, resp.Message)
	}

	// 端点消失时，登出必须已经发出去过了。
	waitGone(t, endpoint, 15*time.Second)
	if h.portal.Count("/por/logout.csp") == 0 {
		t.Fatal("端点消失前没有登出：restart 会和新进程抢账号名额")
	}

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("RunServer 没有退出")
	}
}

// serve 在临时端点上跑起服务进程，返回端点与退出信号。
func serve(t *testing.T, h *harness) (string, chan error) {
	t.Helper()
	endpoint := ipc.EndpointFor(filepath.Join(t.TempDir(), "config.yaml"))
	done := make(chan error, 1)
	go func() { done <- RunServer(h.svc, endpoint) }()
	waitReady(t, endpoint)
	return endpoint, done
}

// closeServer 收尾：服务已经被 Close 过就只等它退出。
func closeServer(t *testing.T, h *harness, done chan error) {
	t.Helper()
	h.svc.Close()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("RunServer 没有退出")
	}
}

// waitReady 等到端点开始应答。
func waitReady(t *testing.T, endpoint string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if resp := tryRequest(endpoint, ipc.Request{Command: ipc.CmdPing}); resp.Code == ipc.CodeOK {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("服务进程没有就绪")
}

// waitGone 等到端点不再应答。
func waitGone(t *testing.T, endpoint string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if tryRequest(endpoint, ipc.Request{Command: ipc.CmdPing}).Code != ipc.CodeOK {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("服务进程在超时前没有退出")
}

// request 发一条请求并返回响应。
func request(t *testing.T, endpoint string, req ipc.Request) ipc.Response {
	t.Helper()
	resp := tryRequest(endpoint, req)
	if resp.Code == 0 {
		t.Fatalf("请求 %s 没有得到响应", req.Command)
	}
	return resp
}

// tryRequest 发一条请求；失败时返回零值响应。
func tryRequest(endpoint string, req ipc.Request) ipc.Response {
	conn, err := ipc.Dial(endpoint)
	if err != nil {
		return ipc.Response{}
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return ipc.Response{}
	}
	if err := ipc.WriteRequest(conn, req); err != nil {
		return ipc.Response{}
	}
	resp, err := ipc.ReadResponse(bufio.NewReader(conn))
	if err != nil {
		return ipc.Response{}
	}
	return resp
}
