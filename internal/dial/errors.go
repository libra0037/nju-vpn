package dial

import (
	"context"
	"errors"
	"io"
	"net"
)

// Error 保留底层类别供 errors.Is/As 使用，但文本不回显地址、URL 或响应体。
type Error struct {
	Op    string
	Cause error
}

func (e *Error) Error() string {
	reason := "失败"
	var nerr net.Error
	switch {
	case errors.Is(e.Cause, context.Canceled):
		reason = "已取消"
	case errors.Is(e.Cause, context.DeadlineExceeded):
		reason = "超时"
	case errors.As(e.Cause, &nerr) && nerr.Timeout():
		reason = "超时"
	case errors.Is(e.Cause, io.EOF), errors.Is(e.Cause, io.ErrUnexpectedEOF):
		reason = "失败（对端提前关闭连接）"
	}
	return e.Op + reason
}
func (e *Error) Unwrap() error { return e.Cause }
func Wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	return &Error{Op: op, Cause: err}
}
