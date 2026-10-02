package main

import (
	"errors"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

const (
	maxLogBytes   = 4 << 20
	maxLogBackups = 2
	daemonLogEnv  = "NJUVPN_DAEMON_LOG"
)

// 服务进程拥有日志文件；最多当前文件及两份备份，共 12 MiB。
type rotatingLog struct {
	mu   sync.Mutex
	path string
	file *os.File
	size int64
}

func openRotatingLog(path string) (*rotatingLog, error) {
	for i := 1; i <= maxLogBackups; i++ {
		backup := path + "." + strconv.Itoa(i)
		if _, err := os.Lstat(backup); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return nil, err
		}
		f, err := openLogFile(backup)
		if err != nil {
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
	}
	f, err := openLogFile(path)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &rotatingLog{path: path, file: f, size: info.Size()}, nil
}

func openLogFile(path string) (*os.File, error) {
	f, err := openPrivateLog(path)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = errors.New("日志路径不是普通文件")
	}
	if err == nil {
		err = f.Chmod(0600)
	}
	// 上限也适用于已有文件，避免启动时带入无界的历史日志。
	if err == nil && info.Size() > maxLogBytes {
		err = f.Truncate(maxLogBytes)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	if _, err := f.Seek(0, 2); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func (l *rotatingLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(p) > maxLogBytes {
		return 0, errors.New("日志单条记录超过预算")
	}
	if l.size+int64(len(p)) > maxLogBytes {
		if err := l.file.Close(); err != nil {
			return 0, err
		}
		for i := maxLogBackups; i > 1; i-- {
			if err := os.Rename(l.path+"."+strconv.Itoa(i-1), l.path+"."+strconv.Itoa(i)); err != nil && !os.IsNotExist(err) {
				return 0, err
			}
		}
		if err := os.Rename(l.path, l.path+".1"); err != nil {
			return 0, err
		}
		f, err := openLogFile(l.path)
		if err != nil {
			return 0, err
		}
		l.file, l.size = f, 0
	}
	n, err := l.file.Write(p)
	l.size += int64(n)
	return n, err
}

func (l *rotatingLog) Close() error { l.mu.Lock(); defer l.mu.Unlock(); return l.file.Close() }

func daemonLogger() (func(), error) {
	path := os.Getenv(daemonLogEnv)
	if path == "" {
		return func() {}, nil
	}
	writer, err := openRotatingLog(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	log.SetOutput(writer)
	return func() { _ = writer.Close() }, nil
}
