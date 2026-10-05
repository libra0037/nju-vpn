//go:build windows

package ipc

import (
	"errors"
	"fmt"
	"net"
	"os/user"
	"strings"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// pipePrefix 是命名管道的命名空间前缀。
const pipePrefix = `\\.\pipe\`

// ErrEmptyEndpoint 表示调用方没有解析出 IPC 端点。
var ErrEmptyEndpoint = errors.New("IPC 端点为空")

func isPlatformDisconnect(err error) bool {
	return errors.Is(err, windows.ERROR_BROKEN_PIPE) ||
		errors.Is(err, windows.ERROR_NO_DATA) ||
		errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED)
}

// endpointPath 把实例标识拼成命名管道名。
//
// 管道名是全局命名空间、所有用户共用，所以必须带实例标识：否则同一台机器上
// 第二个实例既起不来（名字被占），CLI 也会把命令发给第一个实例。
func endpointPath(id string) string { return pipePrefix + "njuvpn-" + id }

// Listen 在命名管道上监听。
//
// 管道必须显式指定访问控制：不传 SecurityDescriptor 时 DACL 由运行账户的
// 令牌推导，并不等于只有创建者能访问，而这条通道能提交验证码、启动隧道。
func Listen(endpoint string) (net.Listener, error) {
	if endpoint == "" {
		return nil, ErrEmptyEndpoint
	}
	if !strings.HasPrefix(endpoint, pipePrefix) {
		return nil, fmt.Errorf("命名管道端点必须以 %s 开头，收到 %q", pipePrefix, endpoint)
	}

	sddl, err := currentUserSDDL()
	if err != nil {
		// 拿不到 SID 时不能退化成仅 SYSTEM 与管理员继续启动：那样服务进程
		// 自己都连不上自己的管道，却仍然占着这个名字，第二个实例也起不来，
		// 用户只能手工去杀进程。
		return nil, err
	}

	cfg := &winio.PipeConfig{SecurityDescriptor: sddl}
	ln, err := winio.ListenPipe(endpoint, cfg)
	if err != nil {
		// 管道名是全局命名空间：最常见的原因就是同机上另一个实例占着
		// 这个名字（端点没按配置派生，或两份配置被算成了同一个实例）。
		return nil, fmt.Errorf("监听命名管道 %s: %w（同机多实例请确认每份配置派生出不同的端点）", endpoint, err)
	}
	return ln, nil
}

// currentUserSDDL 显式指定管道的访问控制。
func currentUserSDDL() (string, error) {
	const base = "D:(A;;GA;;;SY)(A;;GA;;;BA)"
	u, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("取不到当前用户的 SID，无法为命名管道设置访问控制: %w", err)
	}
	if u.Uid == "" {
		return "", errors.New("取不到当前用户的 SID，无法为命名管道设置访问控制")
	}
	return base + "(A;;GA;;;" + u.Uid + ")", nil
}

// Dial 连接服务进程。
func Dial(endpoint string) (net.Conn, error) {
	if endpoint == "" {
		return nil, ErrEmptyEndpoint
	}
	timeout := dialTimeout
	conn, err := winio.DialPipe(endpoint, &timeout)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return nil, ErrNotRunning
		}
		return nil, fmt.Errorf("连接服务进程 %s: %w（服务进程是否在运行？）", endpoint, err)
	}
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		conn.Close()
		return nil, ErrUntrustedPeer
	}
	if err := verifyPipeServer(conn, current.User.Sid); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func verifyPipeServer(conn net.Conn, expectedSID *windows.SID) error {
	f, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return ErrUntrustedPeer
	}
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(windows.Handle(f.Fd()), &pid); err != nil {
		return ErrUntrustedPeer
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ErrUntrustedPeer
	}
	defer windows.CloseHandle(process)
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return ErrUntrustedPeer
	}
	defer token.Close()
	owner, err := token.GetTokenUser()
	if err != nil {
		return ErrUntrustedPeer
	}
	if expectedSID == nil || !owner.User.Sid.Equals(expectedSID) {
		return ErrUntrustedPeer
	}
	return nil
}
