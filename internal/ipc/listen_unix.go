//go:build !windows

package ipc

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// DefaultEndpoint 返回当前平台的默认端点。
func DefaultEndpoint() string { return "/run/njuvpn.sock" }

// Listen 在 Unix 域套接字上监听。
//
// 套接字文件的权限是 0600：这个通道能启动隧道、提交验证码，
// 不能让它被同机的其他用户连上。
func Listen(endpoint string) (net.Listener, error) {
	if endpoint == "" {
		endpoint = DefaultEndpoint()
	}

	if err := os.MkdirAll(filepath.Dir(endpoint), 0o755); err != nil {
		return nil, fmt.Errorf("创建套接字目录: %w", err)
	}

	// 上一次异常退出可能留下陈旧的套接字文件。
	if _, err := os.Stat(endpoint); err == nil {
		if err := os.Remove(endpoint); err != nil {
			return nil, fmt.Errorf("清理旧套接字 %s: %w", endpoint, err)
		}
	}

	ln, err := net.Listen("unix", endpoint)
	if err != nil {
		return nil, fmt.Errorf("监听 %s: %w", endpoint, err)
	}
	if err := os.Chmod(endpoint, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("设置套接字权限: %w", err)
	}
	return ln, nil
}

// Dial 连接服务进程。
func Dial(endpoint string) (net.Conn, error) {
	if endpoint == "" {
		endpoint = DefaultEndpoint()
	}
	conn, err := net.Dial("unix", endpoint)
	if err != nil {
		return nil, fmt.Errorf("连接服务进程 %s: %w（服务是否在运行？）", endpoint, err)
	}
	return conn, nil
}
