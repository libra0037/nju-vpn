//go:build !windows

package main

import "syscall"

// detachedProcAttr 让服务进程自成会话。
//
// 这样 CLI 退出（或被 Ctrl-C 带走、终端关闭）时它不受影响，
// 也不会跟着终端一起收到 SIGHUP。
func detachedProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
