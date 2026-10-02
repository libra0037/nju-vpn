package main

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func openPrivateLog(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.FILE_APPEND_DATA|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ, nil, windows.OPEN_ALWAYS, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		windows.CloseHandle(h)
		return nil, errors.New("日志路径不能是链接或重解析点")
	}
	return os.NewFile(uintptr(h), path), nil
}
