package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/libra0037/nju-vpn/internal/config"
	"github.com/libra0037/nju-vpn/internal/ipc"
)

const (
	// serviceStartTimeout 是等待刚拉起的服务进程就绪的上限。启动只做配置加载
	// 与私钥生成（首次运行时），通常远快于这个值。
	serviceStartTimeout = 10 * time.Second
	// serviceStopTimeout 是等待服务进程退出的上限（含一次登出请求）。
	//
	// 服务进程是先登出、再关监听（这样"端点不再响应"就等于"会话已释放"），
	// 所以这个上限要能覆盖一次登出：登出自身有 10 秒超时，加上收尾的等待。
	serviceStopTimeout = 30 * time.Second
	// pingTimeout 是单次探活的超时。
	pingTimeout = 500 * time.Millisecond
)

// serviceEndpoint 解析服务进程的 IPC 端点。
func serviceEndpoint(configPath string) (string, error) {
	return endpointFor(configPath)
}

// serviceLogPath 让服务进程的日志落在配置文件旁边。
//
// 被 CLI 拉起的服务进程没有控制台，日志必须有地方去；放在配置旁边的好处是
// "启动失败"时用户知道该看哪个文件。文件名带配置名：同一目录下放多份配置时
// 不该共用一份日志，多实例的行交错在一起，排查时容易张冠李戴。
func serviceLogPath(configPath string) string {
	path := configPath
	if path == "" {
		path = config.DefaultPath()
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "njuvpn.log"
	}
	return filepath.Join(dir, logFileName(path))
}

// logFileName 给日志文件取名：njuvpn-<配置名>.log。
//
// 配置名里只保留可移植的字符，剩下的换成下划线：这个值来自命令行给的
// 路径，不该把路径分隔符之类的东西带进文件名。
func logFileName(configPath string) string {
	base := strings.TrimSuffix(filepath.Base(configPath), filepath.Ext(configPath))
	if base == "" || base == "." {
		base = "default"
	}
	var b strings.Builder
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return "njuvpn-" + b.String() + ".log"
}

// pingService 探活：连得上并得到 pong 才算服务进程在运行。
func pingService(endpoint string) error {
	conn, err := ipc.Dial(endpoint)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(pingTimeout)); err != nil {
		return err
	}
	if err := ipc.WriteRequest(conn, ipc.Request{Command: ipc.CmdPing}); err != nil {
		return err
	}
	resp, err := ipc.ReadResponse(bufio.NewReader(conn))
	if err != nil {
		return err
	}
	if resp.Code != ipc.CodeOK {
		return fmt.Errorf("服务进程返回 %d: %s", resp.Code, resp.Message)
	}
	return nil
}

// ensureService 确保服务进程在运行：连不上就拉起一个。
//
// 服务进程由 CLI 按需拉起，而不是装成系统服务——它不需要任何特权，
// 也只在你要用的时候才有存在意义。
func ensureService(configPath string) error {
	endpoint, err := serviceEndpoint(configPath)
	if err != nil {
		return err
	}
	if err := pingService(endpoint); err == nil {
		return nil
	}

	logPath := serviceLogPath(configPath)
	if err := spawnService(configPath, logPath); err != nil {
		return err
	}
	log.Printf("已拉起服务进程（日志: %s）", logPath)

	deadline := time.Now().Add(serviceStartTimeout)
	for time.Now().Before(deadline) {
		if err := pingService(endpoint); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("服务进程在 %s 内没有就绪，请查看日志 %s", serviceStartTimeout, logPath)
}

// spawnService 以脱离终端的方式启动服务进程。
func spawnService(configPath, logPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("定位可执行文件: %w", err)
	}

	args := []string{"run"}
	if configPath != "" {
		args = append(args, "-config", configPath)
	}

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("打开服务日志 %s: %w", logPath, err)
	}

	cmd := exec.Command(exe, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Stdin = nil
	cmd.SysProcAttr = detachedProcAttr()
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return fmt.Errorf("启动服务进程: %w", err)
	}
	// 不等它：服务进程要在 CLI 退出之后继续跑。
	go func() {
		_ = cmd.Wait()
		logFile.Close()
	}()
	return nil
}

// shutdownService 请服务进程收尾退出（它会先登出再退出）。
func shutdownService(endpoint string) error {
	conn, err := ipc.Dial(endpoint)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(serviceStopTimeout)); err != nil {
		return err
	}
	if err := ipc.WriteRequest(conn, ipc.Request{Command: ipc.CmdShutdown}); err != nil {
		return err
	}
	resp, err := ipc.ReadResponse(bufio.NewReader(conn))
	if err != nil {
		return err
	}
	if resp.Code != ipc.CodeOK {
		return fmt.Errorf("服务进程返回 %d: %s", resp.Code, resp.Message)
	}
	fmt.Println(resp.Message)
	return nil
}

// waitServiceGone 等到服务进程真的退出（端点不再响应）。
func waitServiceGone(endpoint string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := pingService(endpoint); err != nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("服务进程在 %s 内没有退出（可能卡在登出）", timeout)
}
