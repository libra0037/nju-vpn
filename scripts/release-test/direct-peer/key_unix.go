//go:build !windows

package main

import (
	"os"
	"syscall"
)

// 文件类型在打开后的描述符上校验；O_NONBLOCK 避免先等待 FIFO 写端。
func openKey(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
