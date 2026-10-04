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
	Code int
}

func (e *ErrCodeRejected) Error() string {
	return fmt.Sprintf("服务端拒绝（%d）", e.Code)
}

// ErrSessionGone 表示会话已经失效，需要重新登录。
type ErrSessionGone struct {
	Code int
}

func (e *ErrSessionGone) Error() string {
	return fmt.Sprintf("会话已失效（%d）", e.Code)
}

// ProtocolError 表示服务端返回的内容不符合预期（长度不足、字段缺失等）。
// 协议层任何时候都不 panic，取值失败一律返回它。
type ProtocolError struct {
	What string
}

// TLS 阶段类别供本地诊断使用，底层原因仍通过错误链保留。
var (
	ErrControlTLS = errors.New("控制面 TLS 验证失败")
	ErrNodeTLS    = errors.New("隧道节点 TLS 握手失败")
)

func (e *ProtocolError) Error() string {
	return "协议错误: " + e.What
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
