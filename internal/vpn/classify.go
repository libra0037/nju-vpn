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

// smsFreshThreshold 是"这次真的发出去了"的倒计时下限。
//
// 服务端在冷却期内会**把上次发送时的响应原样返回**，连
// "验证码已发送到您的手机" 这句文案都不改，唯一变化的是倒计时：
//
//	真发送   SmsSendInterval = 179 / 178   （窗口顶部，约等于整个窗口）
//	冷却期内 SmsSendInterval = 102 / 48    （上一个窗口的剩余时间）
//
// 所以只能靠倒计时是否接近窗口长度来区分。窗口实测约 180 秒，
// 这里取 150 秒留出余量。
const smsFreshThreshold = 150

// classifySMSRequest 判断"发送验证码"请求的结果。
//
// 返回值约定：
//   - state 非 nil：服务端受理了这次请求；
//   - err 非 nil：这次请求失败，需要报给调用方。
//
// 关键区分：ErrSMSSent 表示**这次真的发出了一条新短信**；
// ErrSMSStillValid 表示还在冷却期、没有重发（上一条验证码仍然有效）。
// 早先按"ErrorCode=1 + 手机号字段"判断已发送，结果在冷却期里骗用户
// 去等一条不会来的短信——真机实测踩到过。
func classifySMSRequest(body []byte) (state error, err error) {
	s := string(body)

	if strings.Contains(s, "<ErrorCode>1</ErrorCode>") {
		cooldown := smsCooldownSeconds(s)
		switch {
		case cooldown >= smsFreshThreshold:
			return fmt.Errorf("%w（%d 秒内请勿重复请求）", ErrSMSSent, cooldown), nil
		case cooldown > 0:
			return fmt.Errorf("%w（还需等待 %d 秒）", ErrSMSStillValid, cooldown), nil
		default:
			// 拿不到倒计时就无法区分，按"已发送"提示，并让用户知道
			// 若没收到可以重试。
			return ErrSMSSent, nil
		}
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

// smsCooldownRe 匹配错误文本里嵌的倒计时。两种文案都要认：
// "179 秒内请勿重复请求"（真的发了）与"还需等待 102 秒"（冷却期内没重发）。
var smsCooldownRe = regexp.MustCompile("([0-9]+) 秒")

// SMSCooldown 从错误里取出前端按钮的禁用倒计时。
// 这只影响"能否立刻再点一次发送"，与验证码是否有效无关。
// 解析不出来时返回 0。
func SMSCooldown(err error) time.Duration {
	if err == nil {
		return 0
	}
	m := smsCooldownRe.FindStringSubmatch(err.Error())
	if m == nil {
		return 0
	}
	secs, convErr := strconv.Atoi(m[1])
	if convErr != nil || secs <= 0 {
		return 0
	}
	return time.Duration(secs) * time.Second
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
