//go:build !windows

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestReadKeyRejectsFIFOWithoutWriter(t *testing.T) {
	const childPathEnv = "NJUVPN_TEST_KEY_FIFO"
	if path := os.Getenv(childPathEnv); path != "" {
		if _, err := readKey(path); err == nil {
			t.Fatal("FIFO 被接受为密钥文件")
		}
		return
	}
	path := filepath.Join(t.TempDir(), "key.fifo")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	// 用子进程隔离退回阻塞打开的缺陷；超时会终止并等待，不留下读取协程。
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestReadKeyRejectsFIFOWithoutWriter$")
	cmd.Env = append(os.Environ(), childPathEnv+"="+path, "GORACE="+os.Getenv("GORACE")+" atexit_sleep_ms=0")
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatal("无写端 FIFO 的打开未及时拒绝")
	}
	if err != nil {
		t.Fatalf("读取子进程失败：%v\n%s", err, output)
	}
}
