//go:build !windows

package ipc

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// DefaultEndpoint 返回当前平台的默认端点。
//
// 优先用 $XDG_RUNTIME_DIR：它天然是 0700 且按用户隔离，不需要任何特权。
// 取不到时退回自己的临时目录（同样 0700），而不是所有人都能写的 /tmp 根目录。
func DefaultEndpoint() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "njuvpn.sock")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("njuvpn-%d", os.Getuid()), "njuvpn.sock")
}

// dialProbeTimeout 是探测"这个套接字上还有没有活实例"的超时。
const dialProbeTimeout = 300 * time.Millisecond

// dialTimeout 是连接服务进程的超时，与 Windows 侧保持一致。
const dialTimeout = 5 * time.Second

// Listen 在 Unix 域套接字上监听。
//
// 套接字与目录都收紧到属主专用：这个通道能启动隧道、提交验证码。
func Listen(endpoint string) (net.Listener, error) {
	if endpoint == "" {
		endpoint = DefaultEndpoint()
	}

	// 0700 的目录：$XDG_RUNTIME_DIR 本来就是这个权限，
	// 回落到 /tmp 下的私有目录时由这里创建。
	if err := os.MkdirAll(filepath.Dir(endpoint), 0o700); err != nil {
		return nil, fmt.Errorf("创建套接字目录: %w", err)
	}

	if err := removeStaleSocket(endpoint); err != nil {
		return nil, err
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

// removeStaleSocket 清理上次异常退出留下的套接字。
//
// 只删"确认是套接字、属于当前用户、且没有活实例"的文件：
// 旧实现无条件 os.Remove，端点写错时（例如指向一个普通文件）会把它删掉，
// 运行中的第二个实例也会把前一个的套接字摘掉。
func removeStaleSocket(endpoint string) error {
	fi, err := os.Lstat(endpoint)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("检查套接字 %s: %w", endpoint, err)
	}

	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("端点 %s 已存在且不是套接字，拒绝覆盖", endpoint)
	}
	if uid, ok := ownerUID(fi); ok && uid != os.Getuid() {
		return fmt.Errorf("端点 %s 属于其他用户", endpoint)
	}

	if conn, err := net.DialTimeout("unix", endpoint, dialProbeTimeout); err == nil {
		conn.Close()
		return fmt.Errorf("已有服务进程在监听 %s", endpoint)
	}

	if err := os.Remove(endpoint); err != nil {
		return fmt.Errorf("清理旧套接字 %s: %w", endpoint, err)
	}
	return nil
}

// ownerUID 取出文件属主。
func ownerUID(fi os.FileInfo) (int, bool) {
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(stat.Uid), true
}

// Dial 连接服务进程。
func Dial(endpoint string) (net.Conn, error) {
	if endpoint == "" {
		endpoint = DefaultEndpoint()
	}
	// 带超时：服务进程活着但不再 accept 时，没有超时的 connect 会永久挂住，
	// 客户端连 SetDeadline 都执行不到。
	conn, err := net.DialTimeout("unix", endpoint, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("连接服务进程 %s: %w（服务是否在运行？）", endpoint, err)
	}
	return conn, nil
}
