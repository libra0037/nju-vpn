package ztna

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestDecodeEnvelopeCodeClasses 验证控制面错误码的归类：只有 75500002 算
// "会话失效"，其余一律按"被拒绝"处理并原样带上服务端的 code 与 message。
//
// 凭字面猜其余几个码的代价很实在：75500000 在口令接口表示"凭据错误"（实测），
// 在别处可能是会话过期；75500001 / 75500005 / 75500006 在五家参考实现与实机
// 记录里都没有来源。猜成"会话失效"会把用户登出，猜成"账号已在别处登录"会把
// 排查引到根本没发生的方向。
func TestDecodeEnvelopeCodeClasses(t *testing.T) {
	cases := []struct {
		code       int
		message    string
		sessionArg bool
		wantGone   bool
	}{
		{75500002, "会话已失效", true, true},
		{75500002, "会话已失效", false, false}, // 口令那一步不走会话类归类
		{75500000, "会话过期", true, false},
		{75500001, "登录过程超时", true, false},
		{75500005, "验证码错误", true, false},
		{75500006, "already online", true, false},
	}
	for _, c := range cases {
		raw := []byte(fmt.Sprintf(`{"code":%d,"message":%q}`, c.code, c.message))
		_, err := decodeEnvelope(raw, c.sessionArg)
		if err == nil {
			t.Fatalf("code=%d 应当报错", c.code)
		}
		var gone *ErrSessionGone
		if got := errors.As(err, &gone); got != c.wantGone {
			t.Errorf("code=%d（sessionCodes=%v）：会话失效=%v，期望 %v（%v）",
				c.code, c.sessionArg, got, c.wantGone, err)
		}
		if c.wantGone {
			continue
		}
		var rejected *ErrCodeRejected
		if !errors.As(err, &rejected) {
			t.Errorf("code=%d 应报成被拒绝，得到 %v", c.code, err)
			continue
		}
		if rejected.Code != c.code || strings.Contains(rejected.Error(), c.message) {
			t.Errorf("错误须保留 code 并隐藏服务端消息，得到 %+v", rejected)
		}
	}

	// 成功路径：code 0 时把 data 摘出来。
	data, err := decodeEnvelope([]byte(`{"code":0,"message":"","data":{"vip":"172.16.0.9"}}`), true)
	if err != nil {
		t.Fatalf("code 0 不该报错: %v", err)
	}
	if string(data) != `{"vip":"172.16.0.9"}` {
		t.Errorf("取出的 data = %s", data)
	}
}
