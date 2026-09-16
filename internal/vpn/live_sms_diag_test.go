package vpn

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestLiveSMSDiagnostic 把 /por/login_sms.csp 的原始响应打出来。
//
// 这个接口在冷却期内会把上次的响应原样返回（连文案都不改），只改倒计时，
// 所以"到底有没有真的发短信"必须看原文判断。服务端一旦调整字段语义，
// 用这个用例重新取样本，再更新 classifySMSRequest 的判据。
//
// 注意：它会重新登录，作废当前待验证的会话，且可能发出一条短信。
func TestLiveSMSDiagnostic(t *testing.T) {
	cfg := liveConfig(t)
	client := liveClient(t, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	twfID, err := client.webLogin(ctx, cfg.Username, cfg.Password)
	if err != nil {
		if authErr, ok := AsAuthRequired(err); ok {
			twfID = authErr.TwfID
			t.Logf("登录停在二次验证: %v", authErr.Kind)
		} else {
			t.Fatalf("登录失败: %v", err)
		}
	}
	t.Logf("TwfID: %s", redact(twfID))

	dump := func(label string) {
		raw, err := client.do(ctx, "POST", "/por/login_sms.csp?apiversion=1", nil, twfID)
		if err != nil {
			t.Logf("[%s] 请求失败: %v", label, err)
			return
		}
		os.Stdout.WriteString("=== " + label + " ===\n" + string(raw) + "\n")
		t.Logf("[%s] %d 字节", label, len(raw))
	}

	dump("第一次请求")
	wait := os.Getenv("NJUVPN_LIVE_WAIT")
	if wait == "" {
		return
	}
	d, _ := time.ParseDuration(wait)
	t.Logf("等待 %s 后再次请求", d)
	time.Sleep(d)
	dump("第二次请求")
}
