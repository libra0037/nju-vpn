//go:build windows

package ipc

import (
	"fmt"
	"net"
	"os/user"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
)

// pipePrefix 是命名管道的命名空间前缀。
const pipePrefix = `\\.\pipe\`

// DefaultEndpoint 返回当前平台的默认端点。Windows 下固定用命名管道。
func DefaultEndpoint() string { return pipePrefix + "njuvpn" }

// Listen 在命名管道上监听。
//
// 管道必须显式指定访问控制：不传 SecurityDescriptor 时 DACL 由运行账户的
// 令牌推导，并不等于"只有创建者能访问"，而这条通道能提交验证码、启动隧道。
func Listen(endpoint string) (net.Listener, error) {
	if endpoint == "" {
		endpoint = DefaultEndpoint()
	}
	if !strings.HasPrefix(endpoint, pipePrefix) {
		return nil, fmt.Errorf("Windows 下的 IPC 端点必须是命名管道（以 %s 开头），收到 %q", pipePrefix, endpoint)
	}

	cfg := &winio.PipeConfig{SecurityDescriptor: currentUserSDDL()}
	ln, err := winio.ListenPipe(endpoint, cfg)
	if err != nil {
		return nil, fmt.Errorf("监听命名管道 %s: %w", endpoint, err)
	}
	return ln, nil
}

// currentUserSDDL 只允许当前用户、SYSTEM 与管理员访问管道。
func currentUserSDDL() string {
	const base = "D:(A;;GA;;;SY)(A;;GA;;;BA)"
	u, err := user.Current()
	if err != nil || u.Uid == "" {
		// 拿不到 SID 时退化成"仅 SYSTEM 与管理员"：宁可自己连不上，
		// 也不要把能提交验证码的通道对外开放。
		return base
	}
	return base + "(A;;GA;;;" + u.Uid + ")"
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

// VerifyPeer 在 Windows 上不做额外校验：管道的访问控制已经在 Listen 时指定。
func VerifyPeer(endpoint string) error {
	if endpoint == "" {
		endpoint = DefaultEndpoint()
	}
	if !strings.HasPrefix(endpoint, pipePrefix) {
		return fmt.Errorf("Windows 下的 IPC 端点必须是命名管道，收到 %q", endpoint)
	}
	return nil
}
