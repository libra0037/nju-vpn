//go:build !windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func openPrivateLog(path string) (*os.File, error) {
	dir, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	st, ok := dir.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Getuid()) || dir.Mode().Perm()&0022 != 0 {
		return nil, errors.New("日志目录须由当前用户拥有且其他用户不可写")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err == nil {
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(os.Getuid()) {
			err = errors.New("日志文件属主不是当前用户")
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
