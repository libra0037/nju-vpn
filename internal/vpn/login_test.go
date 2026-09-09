package vpn

import (
	"errors"
	"testing"
)

// 服务端"短信已发出"的真实响应。
//
// IS_IN_PERIOD / SmsSendInterval / g_DisableTime 描述的是本次发送之后前端按钮的
// 禁用倒计时，不是"没有发送"。早先把这个字段解读反了，导致每条实际发出的短信
// 都被误报成"未重发"。
const smsSentResp = `<?xml version="1.0" encoding="utf-8"?>
<Auth>
	<SmsSendInterval>178</SmsSendInterval>
	<IS_IN_PERIOD>1</IS_IN_PERIOD>
	<T_SMSTITLE></T_SMSTITLE>
	<ISLBENABLED>0</ISLBENABLED>
	<T_SMSINFOR>验证码已发送到您的手机：198****4391，请查收！</T_SMSINFOR>
	<Message><![CDATA[auth result.]]></Message>
	<USER_PHONE>****</USER_PHONE>
	<SMS_INTERVAL>178</SMS_INTERVAL>
	<CURRENT_PHONE></CURRENT_PHONE>
	<ErrorCode>1</ErrorCode>
	<SMS_SENDTYPE>NEW_HTTPS</SMS_SENDTYPE>
</Auth>`

// 会话无效时调用发送接口的响应。
const smsInvalidSessionResp = `<?xml version="1.0" encoding="utf-8"?>
<Auth>
	<Message><![CDATA[unexpected user service]]></Message>
	<ErrorCode>20026</ErrorCode>
</Auth>`

func TestClassifySMSRequestSent(t *testing.T) {
	// 这是发送成功的响应，必须报"已发送"，不能报"未重发"。
	state, err := classifySMSRequest([]byte(smsSentResp))
	if err != nil {
		t.Fatalf("不应返回错误: %v", err)
	}
	if !errors.Is(state, ErrSMSSent) {
		t.Errorf("应判定为 ErrSMSSent，实际 %v", state)
	}
}

func TestClassifySMSRequestInvalidSession(t *testing.T) {
	_, err := classifySMSRequest([]byte(smsInvalidSessionResp))
	if err == nil {
		t.Error("会话无效应返回错误")
	}
}

func TestSMSCooldownParsing(t *testing.T) {
	state, err := classifySMSRequest([]byte(smsSentResp))
	if err != nil {
		t.Fatal(err)
	}
	if got := SMSCooldown(state); got.Seconds() != 178 {
		t.Errorf("冷却时间 = %v，期望 178 秒", got)
	}
	if got := SMSCooldown(nil); got != 0 {
		t.Errorf("nil 错误应返回 0，实际 %v", got)
	}
}

func TestClassifySMSAuth(t *testing.T) {
	cases := []struct {
		name  string
		body  string
		want  error
		isErr bool
	}{
		{"成功", "<Auth>Auth sms suc</Auth>", nil, false},
		{"验证码错误", "<Auth>Auth sms failed. invalid code</Auth>", ErrSMSWrongCode, false},
		{"已过期", "<Auth>验证码已过期</Auth>", ErrSMSExpired, false},
		{"过于频繁", "<Auth>发送过于频繁</Auth>", ErrSMSTooMany, false},
		{"未知响应", "<Auth>something else</Auth>", nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state, err := classifySMSAuth([]byte(c.body))
			if c.isErr {
				if err == nil {
					t.Fatal("期望返回错误")
				}
				return
			}
			if err != nil {
				t.Fatalf("不应返回错误: %v", err)
			}
			if c.want == nil {
				if state != nil {
					t.Errorf("期望成功，实际 %v", state)
				}
				return
			}
			if !errors.Is(state, c.want) {
				t.Errorf("状态 = %v，期望 %v", state, c.want)
			}
		})
	}
}

func TestUserMessageStripsPrefix(t *testing.T) {
	state, err := classifySMSRequest([]byte(smsSentResp))
	if err != nil {
		t.Fatal(err)
	}
	wrapped := errors.Join(ERR_NEXT_AUTH_SMS, state)
	if got := UserMessage(wrapped); got == "" || got == wrapped.Error() {
		t.Errorf("UserMessage 未去掉前缀: %q", got)
	}
}

func TestClassifyLogout(t *testing.T) {
	// 服务端登出成功的真实响应。
	ok := `<Auth><Message><![CDATA[logout user success]]></Message><ErrorCode>1</ErrorCode></Auth>`
	if err := classifyLogout([]byte(ok)); err != nil {
		t.Errorf("成功响应不应报错: %v", err)
	}

	// 会话已失效时的真实响应。
	gone := `<Auth><Message><![CDATA[logout user failed]]></Message><ErrorCode>20002</ErrorCode></Auth>`
	if err := classifyLogout([]byte(gone)); !errors.Is(err, ErrLogoutNoSession) {
		t.Errorf("失效会话应返回 ErrLogoutNoSession，实际 %v", err)
	}

	// 其他失败信息要报错，但不应被当成"会话不存在"。
	bad := `<Auth><Message><![CDATA[something bad]]></Message></Auth>`
	if err := classifyLogout([]byte(bad)); err == nil || errors.Is(err, ErrLogoutNoSession) {
		t.Errorf("未知响应应返回一般错误，实际 %v", err)
	}
}
