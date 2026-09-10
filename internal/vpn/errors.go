package vpn

import "errors"

// 服务端要求二次验证时返回的错误种类。
var (
	// ErrAuthSMS 表示服务端要求短信验证码。
	ErrAuthSMS = errors.New("需要短信验证码")
	// ErrAuthTOTP 表示服务端要求 TOTP 验证码。
	ErrAuthTOTP = errors.New("需要 TOTP 验证码")
)

// 短信环节的状态。服务端用同一组响应表达"发了新码""码错了""被限流"，
// 调用方需要区分它们才能给出正确的提示。
var (
	// ErrSMSSent 表示服务端刚刚发了一条新短信。
	ErrSMSSent = errors.New("验证码已发送到手机")
	// ErrSMSWrongCode 表示验证码错误。
	ErrSMSWrongCode = errors.New("验证码错误")
	// ErrSMSExpired 表示验证码已过期，需要重新获取。
	ErrSMSExpired = errors.New("验证码已过期")
	// ErrSMSTooMany 表示请求过于频繁，被服务端限流。
	ErrSMSTooMany = errors.New("短信发送过于频繁")
	// ErrSMSStillValid 表示还在冷却期，服务端没有重发，上一条验证码仍然有效。
	//
	// 这个区分很重要：服务端在冷却期会把上次的响应原样返回，只改倒计时，
	// 不做区分就会提示用户"验证码已发送"，而实际什么都不会来。
	ErrSMSStillValid = errors.New("上一条验证码仍然有效，未重发")
)

// ErrLogoutNoSession 表示服务端没有找到可登出的会话。
var ErrLogoutNoSession = errors.New("服务端没有该会话")

// AuthRequiredError 表示登录停在二次验证处，需要用户提交验证码。
//
// 它同时携带会话标识：验证码必须在**同一次登录会话**里提交，
// 丢了 TwfID 就再也接不上了（这是旧实现里最严重的一个缺口）。
type AuthRequiredError struct {
	// Kind 是 ErrAuthSMS 或 ErrAuthTOTP。
	Kind error
	// TwfID 是停在半路的会话。
	TwfID string
	// State 是短信场景下的附加状态（ErrSMSSent 等），可能为 nil。
	State error
}

func (e *AuthRequiredError) Error() string {
	msg := e.Kind.Error()
	if e.State != nil && e.State.Error() != msg {
		msg += ": " + e.State.Error()
	}
	return msg
}

// Unwrap 让 errors.Is/As 同时匹配 Kind 与 State。
func (e *AuthRequiredError) Unwrap() []error {
	if e.State == nil {
		return []error{e.Kind}
	}
	return []error{e.Kind, e.State}
}

// AsAuthRequired 取出错误里的 AuthRequiredError。
func AsAuthRequired(err error) (*AuthRequiredError, bool) {
	var target *AuthRequiredError
	if errors.As(err, &target) {
		return target, true
	}
	return nil, false
}

// IsAuthCodeError 判断错误是否只是"验证码不对"，会话本身还有效。
// 这类错误不该把整个会话打回 idle。
func IsAuthCodeError(err error) bool {
	return errors.Is(err, ErrSMSWrongCode) ||
		errors.Is(err, ErrSMSExpired) ||
		errors.Is(err, ErrSMSTooMany)
}

// ProtocolError 表示服务端的响应不符合协议。
//
// 所有"对端给了意外数据"的分支都必须返回它，而不是让索引、切片越界
// 或者解引用空指针——那会直接把服务进程带走，而服务端的会话还留着。
type ProtocolError struct {
	Step   string
	Reason string
}

func (e *ProtocolError) Error() string {
	if e.Step == "" {
		return "服务端响应不符合协议: " + e.Reason
	}
	return e.Step + ": 服务端响应不符合协议: " + e.Reason
}
