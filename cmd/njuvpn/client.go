package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/libra0037/nju-vpn/internal/config"
	"github.com/libra0037/nju-vpn/internal/ipc"
)

// clientConfig 是命令行客户端需要的配置：只有 IPC 端点。
//
// CLI 只使用端点字段（配置文件里虽然带着账号口令与 TOTP 密钥，但解析后
// 不读它们），所以配置文件读不到时不该让 CLI 失效——退回默认端点即可。
func clientConfig(configPath string) *config.Config {
	cfg, err := config.LoadForClient(configPath)
	if err == nil {
		return cfg
	}
	// 用户显式指定的配置读不出来时要说一声，否则会连到默认端点上，
	// 而用户以为自己在操作另一台服务进程。
	if configPath != "" {
		fmt.Fprintf(os.Stderr, "%s: 无法加载配置 %s: %v（改用默认端点）\n", prog, configPath, err)
	}
	return &config.Config{}
}

// call 向服务进程发一条请求并返回响应。
//
// 带超时：服务进程可能在等短信验证码、或正在退避重试，
// 没有超时的客户端会一直挂着，而用户看不出发生了什么。
func call(endpoint string, req ipc.Request, timeout time.Duration) (ipc.Response, error) {
	conn, err := ipc.Dial(endpoint)
	if err != nil {
		return ipc.Response{}, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return ipc.Response{}, err
	}

	if err := ipc.WriteRequest(conn, req); err != nil {
		return ipc.Response{}, fmt.Errorf("发送请求: %w", err)
	}
	resp, err := ipc.ReadResponse(bufio.NewReader(conn))
	if err != nil {
		return ipc.Response{}, fmt.Errorf("读取响应: %w", err)
	}
	return resp, nil
}

// endpointOf 解析出 IPC 端点。
func endpointOf(cfg *config.Config) string {
	if cfg != nil && cfg.IPC.Endpoint != "" {
		return cfg.IPC.Endpoint
	}
	return ipc.DefaultEndpoint()
}

// runCommand 是 start/stop/status/auth 的公共实现。
//
// 退出码语义直接由响应状态码决定，不依赖提示文案：
// 200 与 428（需要验证码）算成功，其余算失败。
func runCommand(name string, args []string, req ipc.Request, timeout time.Duration) error {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	configPath := fs.String("config", "", "配置文件路径")
	if _, err := parseInterleaved(fs, args); err != nil {
		return err
	}
	return runAt(endpointOf(clientConfig(*configPath)), req, timeout)
}

// runAt 向指定端点发一条请求，并按响应状态码决定退出码。
func runAt(endpoint string, req ipc.Request, timeout time.Duration) error {
	resp, err := call(endpoint, req, timeout)
	if err != nil {
		return err
	}
	fmt.Println(resp.Message)

	switch resp.Code {
	case ipc.CodeOK:
		return nil
	case ipc.CodeAuthRequired:
		// 需要提交验证码不是错误：脚本据此决定下一步。
		return nil
	default:
		return fmt.Errorf("服务进程返回 %d", resp.Code)
	}
}

// promptCode 从终端读验证码。
func promptCode() (string, error) {
	fmt.Fprint(os.Stderr, "请输入验证码: ")
	var code string
	if _, err := fmt.Scanln(&code); err != nil {
		return "", err
	}
	return strings.TrimSpace(code), nil
}
