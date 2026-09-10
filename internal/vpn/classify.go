package vpn

import (
	"errors"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// redact 把凭据缩短成"能认出来但看不出内容"的形式。
//
// 只保留长度和前缀，不保留尾部：旧实现保留首尾各两个字符，
// 16 字符的 TwfID 会泄漏最后两个字符。
func redact(s string) string {
	if s == "" {
		return "(空)"
	}
	if len(s) <= 8 {
		return fmt.Sprintf("(%d 字节)", len(s))
	}
	return fmt.Sprintf("%s…(%d 字节)", s[:4], len(s))
}

// classifySMSRequest 判断"发送验证码"请求的结果。
//
// 返回值约定：
//   - state 非 nil：服务端受理了这次请求（可能带限流/冷却信息）；
//   - err 非 nil：这次请求失败，需要报给调用方。
//
// 响应里的 IS_IN_PERIOD / SmsSendInterval / g_DisableTime 是**本次发送之后**
// 前端按钮的禁用倒计时，不是"没有发送"的标志——早先把它们解读反了，
// 导致每次实际发出去的短信都被误报成"未重发"。
func classifySMSRequest(body []byte) (state error, err error) {
	s := string(body)

	if smsSent(s) {
		if d := smsCooldownSeconds(s); d > 0 {
			return fmt.Errorf("%w（%d 秒内请勿重复请求）", ErrSMSSent, d), nil
		}
		return ErrSMSSent, nil
	}

	switch {
	case strings.Contains(s, "频繁") || strings.Contains(s, "too many") || strings.Contains(s, "TooMany"):
		return ErrSMSTooMany, nil
	case strings.Contains(s, "未登录") || strings.Contains(s, "unexpected user service"):
		return nil, errors.New("会话无效，无法发送验证码: " + serverMessage(body))
	case strings.Contains(s, "失败") || strings.Contains(s, "fail"):
		return nil, errors.New("发送验证码失败: " + serverMessage(body))
	}
	return nil, errors.New("发送验证码的响应无法识别: " + serverMessage(body))
}

// smsSent 判断响应是否表示"短信已发出"。
// ErrorCode=1 是服务端的成功码，配合手机号字段即可确认。
func smsSent(body string) bool {
	if !strings.Contains(body, "<ErrorCode>1</ErrorCode>") {
		return false
	}
	return strings.Contains(body, "<USER_PHONE>") || strings.Contains(body, "验证码已发送")
}

// smsCooldownSeconds 取出前端按钮的禁用倒计时。
func smsCooldownSeconds(body string) int {
	for _, tag := range []string{"SmsSendInterval", "SMS_INTERVAL"} {
		if v, ok := tagValue([]byte(body), tag); ok {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				return n
			}
		}
	}
	return 0
}

// SMSCooldown 从错误里解析出前端按钮的禁用倒计时。
// 这只影响"能否立刻再点一次发送"，与验证码是否有效无关。
// 解析不出来时返回 0。
func SMSCooldown(err error) time.Duration {
	if err == nil {
		return 0
	}
	m := regexp.MustCompile("([0-9]+) 秒内请勿重复请求").FindStringSubmatch(err.Error())
	if m == nil {
		return 0
	}
	secs, convErr := strconv.Atoi(m[1])
	if convErr != nil || secs <= 0 {
		return 0
	}
	return time.Duration(secs) * time.Second
}

// UserMessage 去掉内部错误的前缀，只保留给用户看的部分。
func UserMessage(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if i := strings.LastIndex(msg, "\n"); i >= 0 {
		msg = msg[i+1:]
	}
	if i := strings.LastIndex(msg, ": "); i >= 0 {
		return msg[i+2:]
	}
	return msg
}

// classifySMSAuth 判断提交验证码的结果。
func classifySMSAuth(body []byte) (state error, err error) {
	s := string(body)
	switch {
	case strings.Contains(s, "Auth sms suc"):
		return nil, nil
	case strings.Contains(s, "过期") || strings.Contains(s, "expire"):
		return ErrSMSExpired, nil
	case strings.Contains(s, "错误") || strings.Contains(s, "invalid") || strings.Contains(s, "Invalid"):
		return ErrSMSWrongCode, nil
	case strings.Contains(s, "频繁") || strings.Contains(s, "too many"):
		return ErrSMSTooMany, nil
	}
	return nil, errors.New("验证码提交的响应无法识别: " + serverMessage(body))
}

// classifyLogout 解析登出响应。
func classifyLogout(body []byte) error {
	if msg, ok := tagValue(body, "Message"); ok {
		msg = strings.TrimSpace(msg)
		log.Printf("登出响应: %s", msg)
		switch msg {
		case "logout user success":
			return nil
		case "logout user failed":
			return ErrLogoutNoSession
		default:
			return fmt.Errorf("登出失败: %s", msg)
		}
	}
	return fmt.Errorf("登出响应无法解析: %s", serverMessage(body))
}

// serverMessage 从服务端返回的 XML 里提取可读的错误信息。
// 直接把整个响应体塞进错误里，日志会变得没法看。
func serverMessage(body []byte) string {
	for _, tag := range []string{"Message", "ErrorMsg", "Note"} {
		if v, ok := tagValue(body, tag); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	if v, ok := tagValue(body, "ErrorCode"); ok {
		return "错误码 " + strings.TrimSpace(v)
	}
	return "服务端返回了未预期的响应"
}
