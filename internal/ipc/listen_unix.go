//go:build !windows

package ipc

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// ErrEmptyEndpoint 表示调用方没有解析出 IPC 端点。
//
// 端点由配置文件的路径派生（见 EndpointFor），解析是调用方的责任：
// 这里不再替调用方挑一个默认端点。否则配置读取失败时会静默连到另一个
// 实例上——stop 与 restart 会打到别人的服务进程。
var ErrEmptyEndpoint = errors.New("IPC 端点为空")

// endpointPath 把实例标识拼成 Unix 域套接字路径。
//
// 优先用 $XDG_RUNTIME_DIR：它天然是 0700 且按用户隔离，不需要任何特权。
// 取不到时退回自己的临时目录（同样 0700），而不是所有人都能写的 /tmp 根目录。
func endpointPath(id string) string {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = filepath.Join(os.TempDir(), fmt.Sprintf("njuvpn-%d", os.Getuid()))
	}
	return filepath.Join(dir, "njuvpn-"+id+".sock")
}

// dialProbeTimeout 是探测这个套接字上还有没有活实例的超时。
const dialProbeTimeout = 300 * time.Millisecond

// dialTimeout 是连接服务进程的超时，与 Windows 侧保持一致。
const dialTimeout = 5 * time.Second

// Listen 在 Unix 域套接字上监听。
//
// 套接字与目录都收紧到属主专用：这个通道能启动隧道、提交验证码。
func Listen(endpoint string) (net.Listener, error) {
	if endpoint == "" {
		return nil, ErrEmptyEndpoint
	}

	if err := ensurePrivateDir(filepath.Dir(endpoint)); err != nil {
		return nil, err
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

// ensurePrivateDir 创建并校验套接字目录。
//
// $XDG_RUNTIME_DIR 正常就是 0700；回退路径（$TMPDIR/njuvpn-<uid>）的名字
// 是可预测的，而 MkdirAll 对已经存在的目录既不报错也不收紧权限。那条路径
// 上，同机其他用户可以抢先建好一个宽松的目录、在里面放上自己的套接字，
// 之后受害者的验证码就发给了那个进程。所以这里自己校验属主与权限。
func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("创建套接字目录: %w", err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("检查套接字目录 %s: %w", dir, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("套接字目录 %s 不是目录", dir)
	}
	if uid, ok := ownerUID(fi); ok && uid != os.Getuid() {
		return fmt.Errorf("套接字目录 %s 属于其他用户，拒绝使用", dir)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		// 属主是自己时收紧权限即可；收不动就宁可失败。
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("套接字目录 %s 权限过宽（%04o）且无法收紧: %w", dir, perm, err)
		}
	}
	return nil
}

// removeStaleSocket 清理上次异常退出留下的套接字。
//
// 只删确认是套接字、属于当前用户、且没有活实例的文件：
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
		return fmt.Errorf("已有服务进程在监听 %s（同一台机器上跑多个实例时，每份配置要用不同的 -config 路径，或显式设置 ipc.endpoint）", endpoint)
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
		return nil, ErrEmptyEndpoint
	}
	// 带超时：服务进程活着但不再 accept 时，没有超时的 connect 会永久挂住，
	// 客户端连 SetDeadline 都执行不到。
	conn, err := net.DialTimeout("unix", endpoint, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("连接服务进程 %s: %w（服务是否在运行？）", endpoint, err)
	}
	return conn, nil
}
