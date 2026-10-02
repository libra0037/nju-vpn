//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoggerRejectsLinkAndWritableDirectory(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	victim := filepath.Join(dir, "victim")
	os.WriteFile(victim, []byte("keep"), 0600)
	link := filepath.Join(dir, "daemon.log")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if l, err := openRotatingLog(link); err == nil {
		l.Close()
		t.Fatal("日志跟随链接")
	}
	data, _ := os.ReadFile(victim)
	if string(data) != "keep" {
		t.Fatal("日志覆盖了链接目标")
	}
	os.Chmod(dir, 0777)
	defer os.Chmod(dir, 0700)
	if l, err := openRotatingLog(filepath.Join(dir, "unsafe.log")); err == nil {
		l.Close()
		t.Fatal("日志使用可被其他用户写入的目录")
	}
}
