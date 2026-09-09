package vpn

import (
	"errors"
	"testing"
)

// 真实的冷却期响应：既有"已发送"的模板文案，又有 IS_IN_PERIOD=1。
const smsInPeriodResp = `<?xml version="1.0" encoding="utf-8"?>
<Auth>
	<SmsSendInterval>178</SmsSendInterval>
	<IS_IN_PERIOD>1</IS_IN_PERIOD>
	<T_SMSINFOR>验证码已发送到您的手机：198****4391，请查收！</T_SMSINFOR>
	<Message><![CDATA[auth result.]]></Message>
	<USER_PHONE>****</USER_PHONE>
	<SMS_INTERVAL>178</SMS_INTERVAL>
	<ErrorCode>1</ErrorCode>
</Auth>`

// 真正发出新码的响应。
const smsSentResp = `<?xml version="1.0" encoding="utf-8"?>
<Auth>
	<IS_IN_PERIOD>0</IS_IN_PERIOD>
	<T_SMSINFOR>验证码已发送到您的手机：198****4391，请查收！</T_SMSINFOR>
	<USER_PHONE>****</USER_PHONE>
	<ErrorCode>1</ErrorCode>
</Auth>`

func TestClassifySMSRequestInPeriod(t *testing.T) {
	// 冷却期优先：即便响应里有"已发送"文案，也必须报告未重发。
	state, err := classifySMSRequest([]byte(smsInPeriodResp))
	if err != nil {
		t.Fatalf("不应返回错误: %v", err)
	}
	if !errors.Is(state, ErrSMSStillValid) {
		t.Errorf("冷却期应判定为 ErrSMSStillValid，实际 %v", state)
	}
}

func TestClassifySMSRequestSent(t *testing.T) {
	state, err := classifySMSRequest([]byte(smsSentResp))
	if err != nil {
		t.Fatalf("不应返回错误: %v", err)
	}
	if !errors.Is(state, ErrSMSSent) {
		t.Errorf("应判定为 ErrSMSSent，实际 %v", state)
	}
}

func TestSMSCooldownParsing(t *testing.T) {
	state, err := classifySMSRequest([]byte(smsInPeriodResp))
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
	state, err := classifySMSRequest([]byte(smsInPeriodResp))
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
