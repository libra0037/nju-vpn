package main

import (
	"testing"

	"golang.org/x/sys/windows"
)

// 原生 ARM64 CI 已遇到 shutdown 获确认后，下一次探活写入已关闭的管道。
// 这些系统错误仅允许继续轮询，不能提前启动另一个服务进程。
func TestWaitServiceGoneAfterNamedPipeDisconnect(t *testing.T) {
	for _, disconnect := range []error{
		windows.ERROR_BROKEN_PIPE,
		windows.ERROR_NO_DATA,
		windows.ERROR_PIPE_NOT_CONNECTED,
	} {
		t.Run(disconnect.Error(), func(t *testing.T) {
			assertWaitServiceGoneAfterDisconnect(t, disconnect)
		})
	}
}
