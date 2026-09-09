//go:build windows

package ipc

import (
	"fmt"
	"net"
	"time"

	"github.com/Microsoft/go-winio"
)

const pipeName = `\\.\pipe\njuvpn`

// DefaultEndpoint 返回当前平台的默认端点。Windows 下固定用命名管道。
func DefaultEndpoint() string { return pipeName }

// Listen 在命名管道上监听。
//
// 管道默认的 ACL 只允许创建者与管理员访问，等价于 Unix 侧的 0600。
func Listen(endpoint string) (net.Listener, error) {
	if endpoint == "" {
		endpoint = DefaultEndpoint()
	}
	ln, err := winio.ListenPipe(endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("监听命名管道 %s: %w", endpoint, err)
	}
	return ln, nil
}

// Dial 连接服务进程。
func Dial(endpoint string) (net.Conn, error) {
	if endpoint == "" {
		endpoint = DefaultEndpoint()
	}
	timeout := 5 * time.Second
	conn, err := winio.DialPipe(endpoint, &timeout)
	if err != nil {
		return nil, fmt.Errorf("连接服务进程 %s: %w（服务是否在运行？）", endpoint, err)
	}
	return conn, nil
}
