//go:build !windows

package config

import (
	"errors"
	"os"
	"syscall"
)

func openConfig(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

func checkIdentityDirectory(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Getuid()) || fi.Mode().Perm()&0o022 != 0 {
		return errors.New("身份配置目录须由当前用户拥有，且其他用户不可写")
	}
	return nil
}
