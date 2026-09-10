//go:build windows

package main

import "syscall"

const (
	// CREATE_NEW_PROCESS_GROUP 让它不接收控制台 Ctrl-C。
	createNewProcessGroup = 0x00000200
	// DETACHED_PROCESS 让它不继承 CLI 的控制台，CLI 退出后继续运行。
	detachedProcess = 0x00000008
)

// detachedProcAttr 让服务进程脱离 CLI 的控制台独立运行。
func detachedProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: createNewProcessGroup | detachedProcess}
}
