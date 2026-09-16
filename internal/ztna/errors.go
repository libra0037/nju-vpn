package ztna

import (
	"errors"
	"fmt"
)

// 协议层对外暴露的错误分类。调用方（服务进程）据此决定状态机走向，
// 不要靠字符串匹配。

// ErrAuthRequired 表示服务端要求二次验证，需要用户提供验证码。
type ErrAuthRequired struct {
	// Kind 是二次验证的类型，目前只有短信。
	Kind string
	// Hint 是给用户看的提示（手机号脱敏、冷却说明等）。
	Hint string
}

func (e *ErrAuthRequired) Error() string { return "需要二次验证: " + e.Hint }

// ErrCodeRejected 表示服务端拒绝了本次登录（口令错误、验证码错误等）。
type ErrCodeRejected struct {
	Code    int
	Message string
}

func (e *ErrCodeRejected) Error() string {
	return fmt.Sprintf("服务端拒绝（%d）: %s", e.Code, e.Message)
}

// ErrSessionGone 表示会话已经失效，需要重新登录。
type ErrSessionGone struct {
	Code    int
	Message string
}

func (e *ErrSessionGone) Error() string {
	return fmt.Sprintf("会话已失效（%d）: %s", e.Code, e.Message)
}

// ProtocolError 表示服务端返回的内容不符合预期（长度不足、字段缺失等）。
// 协议层任何时候都不 panic，取值失败一律返回它。
type ProtocolError struct {
	What string
	Got  string
}

func (e *ProtocolError) Error() string {
	if e.Got == "" {
		return "协议错误: " + e.What
	}
	return fmt.Sprintf("协议错误: %s（收到 %q）", e.What, e.Got)
}

// AsAuthRequired 判断错误链里是否有"需要二次验证"。
func AsAuthRequired(err error) (*ErrAuthRequired, bool) {
	var target *ErrAuthRequired
	if errors.As(err, &target) {
		return target, true
	}
	return nil, false
}

// AsRejected 判断错误链里是否有"服务端拒绝了这次请求"（口令或验证码错）。
func AsRejected(err error) (*ErrCodeRejected, bool) {
	var target *ErrCodeRejected
	if errors.As(err, &target) {
		return target, true
	}
	return nil, false
}
