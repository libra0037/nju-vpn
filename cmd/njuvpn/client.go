package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"njuvpn/internal/config"
	"njuvpn/internal/ipc"
)

// clientConfig 是命令行客户端需要的配置：只有 IPC 端点。
// 客户端不读账号密码，那些只属于服务进程。
func clientConfig(configPath string) (*config.Config, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

// call 向服务进程发一条请求并返回响应。
func call(endpoint string, req ipc.Request) (ipc.Response, error) {
	conn, err := ipc.Dial(endpoint)
	if err != nil {
		return ipc.Response{}, err
	}
	defer conn.Close()

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
func runCommand(name string, args []string, req ipc.Request) error {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	configPath := fs.String("config", "", "配置文件路径")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := clientConfig(*configPath)
	if err != nil {
		return err
	}

	resp, err := call(endpointOf(cfg), req)
	if err != nil {
		return err
	}

	fmt.Println(resp.Message)
	if resp.Code != ipc.CodeOK {
		// 409 表示需要验证码，这不是错误，退出码用 0 更符合脚本预期。
		if resp.Code == ipc.CodeRejected && strings.Contains(resp.Message, "验证码") {
			return nil
		}
		return fmt.Errorf("服务进程返回 %d", resp.Code)
	}
	return nil
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
