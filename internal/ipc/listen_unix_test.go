//go:build !windows

package ipc

import (
	"net"
	"os"
	"syscall"
	"testing"
)

// TestProbeAliveTreatsTimeoutAsRunning 回归：套接字探活超时按"仍在运行"处理。
//
// 服务进程的命令是串行的，正忙着登录、登出或发验证码时 300ms 的探测会超时；
// 把它当成"陈旧套接字"删掉，会让两个进程各自以为自己是唯一实例：旧的那个
// 此后收不到命令，也没人负责登出。
func TestProbeAliveTreatsTimeoutAsRunning(t *testing.T) {
	// nil 表示连上了：那是"有活实例"的另一种表现，由调用方单独处理。
	if probeAlive(nil) {
		t.Error("nil 不该被判成超时")
	}
	timeout := &net.OpError{Op: "dial", Net: "unix", Err: os.ErrDeadlineExceeded}
	if !probeAlive(timeout) {
		t.Error("超时必须按仍在运行处理")
	}
	refused := &net.OpError{Op: "dial", Net: "unix", Err: syscall.ECONNREFUSED}
	if probeAlive(refused) {
		t.Error("连接被拒说明没人监听，应当允许清理")
	}
}
