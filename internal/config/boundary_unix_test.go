//go:build !windows

package config

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestConfigFIFOIsRejectedWithoutWaitingForWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := LoadForClient(path); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("特殊文件被当成配置")
		}
	case <-time.After(time.Second):
		t.Fatal("等待 FIFO 写入者")
	}
}
func TestIdentityWriteRejectsWritableDirectory(t *testing.T) {
	path := writeConfig(t, validConfig, 0600)
	dir := filepath.Dir(path)
	before, _ := os.ReadFile(path)
	os.Chmod(dir, 0777)
	defer os.Chmod(dir, 0700)
	cfg, err := InitializeIdentity(path, func() (string, string, error) { return "id", "key", nil })
	if cfg != nil || err == nil {
		t.Fatal("不安全目录仍允许写回")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("失败仍修改磁盘")
	}
}
