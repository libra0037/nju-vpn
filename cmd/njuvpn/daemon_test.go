package main

import (
	"bufio"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/ipc"
)

// 这一段测的是命令行与"被它拉起的服务进程"之间的那一跳：端点派生、探活、
// 子进程脱离终端、shutdown 握手。单个包里的用例都覆盖不到它，而它一旦坏了，
// 用户看到的是"start 卡住"或者"命令发给了不存在的进程"。
//
// 测试真的去编译当前包并用它当子进程：os.Executable 在测试进程里指向测试
// 二进制，不重新编译就测不到真实形态。
func TestRestartSpawnsAndStopsDaemon(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 的进程与信号语义不同，这一条在 Linux/macOS 上覆盖")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("没有 go 命令，跳过需要编译的集成测试")
	}

	dir := t.TempDir()
	bin := filepath.Join(dir, "njuvpn")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("编译失败: %v", err)
	}

	configPath := filepath.Join(dir, "config.yaml")
	config := strings.Join([]string{
		"server: vpn.test",
		"username: u",
		"password: \"\"",
		"port: 443",
		"mtu: 1320",
		"wireguard:",
		"  listen_port: 51987",
		"  peer_address: 10.66.66.2",
		"log:",
		"  level: info",
		"",
	}, "\n")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	run := func(args ...string) (string, error) {
		t.Helper()
		cmd := exec.Command(bin, args...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	// restart 会拉起服务进程；它不登录，所以不需要服务端。
	if out, err := run("restart", "-config", configPath); err != nil {
		t.Fatalf("restart 失败: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		// 测试结束时把服务进程收掉：它是脱离终端跑的，不会跟着测试进程退出。
		if endpoint, err := endpointFor(configPath); err == nil {
			_ = shutdownDaemon(endpoint)
		}
	})

	out, err := run("status", "-config", configPath)
	if err != nil {
		t.Fatalf("status 失败: %v\n%s", err, out)
	}
	if !strings.Contains(out, string("idle")) {
		t.Errorf("刚拉起的服务进程应处于 idle，得到 %q", out)
	}

	// 启动时生成的两样东西要写回配置文件，否则重启一次就换身份。
	body, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"device_id:", "private_key:"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("配置文件里没有写回 %s:\n%s", want, body)
		}
	}

	// 幂等：再敲一次 restart（先 shutdown 再拉起）。
	if out, err := run("restart", "-config", configPath); err != nil {
		t.Fatalf("第二次 restart 失败: %v\n%s", err, out)
	}
	if out, err := run("status", "-config", configPath); err != nil {
		t.Fatalf("第二次 status 失败: %v\n%s", err, out)
	}

	// stop 在没有隧道时按成功处理：脚本里一句 stop 不该因为"已经停了"失败。
	out, err = run("stop", "-config", configPath)
	if err != nil {
		t.Fatalf("stop 失败: %v\n%s", err, out)
	}
	if !strings.Contains(out, "本来就没有运行") {
		t.Errorf("stop 的文案 = %q", out)
	}

	// 收到 shutdown 之后端点不再响应。
	endpoint, err := endpointFor(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := shutdownDaemon(endpoint); err != nil {
		t.Fatalf("shutdown 失败: %v", err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if err := pingService(endpoint); err != nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("服务进程在 shutdown 之后仍在响应")
}

// shutdownDaemon 直连端点请服务进程退出，供测试收尾用。
func shutdownDaemon(endpoint string) error {
	conn, err := ipc.Dial(endpoint)
	if err != nil {
		return nil // 本来就没在跑
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := ipc.WriteRequest(conn, ipc.Request{Command: ipc.CmdShutdown}); err != nil {
		return err
	}
	_, err = ipc.ReadResponse(bufio.NewReader(conn))
	return err
}

// pongServer 在端点上应答探活，模拟另一个已经就绪的服务进程。
func pongServer(t *testing.T, endpoint string) {
	t.Helper()
	ln, err := ipc.Listen(endpoint)
	if err != nil {
		t.Fatalf("监听测试端点失败: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
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
				_ = ipc.WriteResponse(c, ipc.Response{Code: ipc.CodeOK, Message: "pong 另一个调用拉起的服务进程"})
			}(conn)
		}
	}()
}

// TestWaitServiceReadyAdoptsConcurrentDaemon 验证“我们拉起的子进程退了、但端点
// 上已有另一个服务进程在应答”时按成功处理：并发调用里只有一个能占住端点，
// 输的那个立刻退出，不该让看门狗脚本收到一个 exit 1 的假警报。
func TestWaitServiceReadyAdoptsConcurrentDaemon(t *testing.T) {
	dir := t.TempDir()
	endpoint := filepath.Join(dir, "njuvpn-test.sock")
	logPath := filepath.Join(dir, "service.log")
	if err := os.WriteFile(logPath, []byte("[日志] 启动失败: 端点已被占用\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// 赢家此刻正在就绪：端点晚一小会儿才开始应答。
	go func() {
		time.Sleep(300 * time.Millisecond)
		pongServer(t, endpoint)
	}()

	exited := make(chan error, 1)
	exited <- errors.New("exit status 1")
	if err := waitServiceReady(endpoint, logPath, exited, 10*time.Second); err != nil {
		t.Fatalf("另一个服务进程已就绪时应当按成功处理，得到 %v", err)
	}
}

// TestWaitServiceReadyReportsStartupFailure 验证真的起不来时仍然立刻报错，
// 不会因为上面那条“等一下赢家”的逻辑而把失败吞掉。
func TestWaitServiceReadyReportsStartupFailure(t *testing.T) {
	dir := t.TempDir()
	endpoint := filepath.Join(dir, "njuvpn-test.sock")
	logPath := filepath.Join(dir, "service.log")

	exited := make(chan error, 1)
	exited <- errors.New("exit status 1")
	err := waitServiceReady(endpoint, logPath, exited, 10*time.Second)
	if err == nil {
		t.Fatal("没有任何服务进程应答时应当报错")
	}
	if !strings.Contains(err.Error(), "启动后立即退出") {
		t.Fatalf("错误应当指向启动失败，得到 %v", err)
	}
}
