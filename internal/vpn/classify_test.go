package vpn

import (
	"errors"
	"strings"
	"testing"
)

// 真实响应样本，取自 2026-09-10 的实测（见 HANDOFF 第 6.5 节）。
// 服务端在冷却期内会把上次的响应原样返回，只有倒计时不同，
// 所以这三条样本是分类器的判据依据。
const (
	smsFreshResponse = `<Auth>
	<SmsSendInterval>179</SmsSendInterval>
	<IS_IN_PERIOD>1</IS_IN_PERIOD>
	<T_SMSINFOR>验证码已发送到您的手机：198****4391，请查收！</T_SMSINFOR>
	<Message><![CDATA[auth result.]]></Message>
	<USER_PHONE>****</USER_PHONE>
	<SMS_INTERVAL>179</SMS_INTERVAL>
	<ErrorCode>1</ErrorCode>
	<SMS_SENDTYPE>NEW_HTTPS</SMS_SENDTYPE>
</Auth>`

	smsCooldownResponse = `<Auth>
	<SmsSendInterval>48</SmsSendInterval>
	<IS_IN_PERIOD>1</IS_IN_PERIOD>
	<T_SMSINFOR>验证码已发送到您的手机：198****4391，请查收！</T_SMSINFOR>
	<Message><![CDATA[auth result.]]></Message>
	<USER_PHONE>****</USER_PHONE>
	<SMS_INTERVAL>48</SMS_INTERVAL>
	<ErrorCode>1</ErrorCode>
	<SMS_SENDTYPE>NEW_HTTPS</SMS_SENDTYPE>
</Auth>`
)

// 回归：冷却期内服务端不重发，响应里却仍带着"验证码已发送"的缓存文案，
// 按文案判断会提示用户去等一条不会来的短信。
func TestClassifySMSRequestDistinguishesCooldown(t *testing.T) {
	// 真发送：倒计时在窗口顶部。
	state, err := classifySMSRequest([]byte(smsFreshResponse))
	if err != nil {
		t.Fatalf("真发送不该报错: %v", err)
	}
	if !errors.Is(state, ErrSMSSent) {
		t.Errorf("倒计时 179 应判为已发送，实际 %v", state)
	}
	if errors.Is(state, ErrSMSStillValid) {
		t.Error("已发送不该同时被判为冷却")
	}

	// 冷却期：倒计时是上一个窗口的剩余时间。
	state, err = classifySMSRequest([]byte(smsCooldownResponse))
	if err != nil {
		t.Fatalf("冷却期不该报错: %v", err)
	}
	if !errors.Is(state, ErrSMSStillValid) {
		t.Errorf("倒计时 48 应判为未重发，实际 %v", state)
	}
	if errors.Is(state, ErrSMSSent) {
		t.Error("冷却期绝不能判成已发送")
	}
	if !strings.Contains(state.Error(), "48") {
		t.Errorf("提示里应带上剩余秒数，实际 %q", state.Error())
	}
}

// 倒计时取不到时退化成"已发送"，但必须是成功状态而不是错误。
func TestClassifySMSRequestWithoutInterval(t *testing.T) {
	body := `<Auth><ErrorCode>1</ErrorCode><USER_PHONE>****</USER_PHONE></Auth>`
	state, err := classifySMSRequest([]byte(body))
	if err != nil {
		t.Fatalf("不该报错: %v", err)
	}
	if state == nil {
		t.Fatal("应给出状态")
	}
}

// 限流与失败分支保持原样。
func TestClassifySMSRequestErrors(t *testing.T) {
	state, err := classifySMSRequest([]byte("<Auth>操作频繁</Auth>"))
	if err != nil || !errors.Is(state, ErrSMSTooMany) {
		t.Errorf("限流识别错误: state=%v err=%v", state, err)
	}

	state, err = classifySMSRequest([]byte("<Auth><Message>未登录</Message></Auth>"))
	if err == nil || state != nil {
		t.Errorf("会话无效应报错: state=%v err=%v", state, err)
	}
}
