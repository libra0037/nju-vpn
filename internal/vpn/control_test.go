package vpn

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestControlErrorRetryable(t *testing.T) {
	// 只有暂时性的控制码值得重试。终止性重试会加重服务端的拒绝状态。
	cases := map[byte]bool{
		ControlIPBusy:      true,  // 5：地址被占用，可恢复
		ControlServerReset: false, // 3：多是"建得太密"或"上条会话没释放"，等几分钟再试
		ControlShutdown:    false, // 8：会话不存在，重试无意义
		ControlIPConflict:  false, // 9
		ControlIPKick:      false, // 14
	}
	for code, want := range cases {
		e := &ControlError{Code: code}
		if got := e.Retryable(); got != want {
			t.Errorf("码 %d 的 Retryable() = %v，期望 %v", code, got, want)
		}
	}
}

func TestControlErrorMessageCarriesCodeName(t *testing.T) {
	// 错误信息要能一眼看出是哪个码，否则诊断时只能看十六进制。
	e := &ControlError{Code: ControlShutdown, Context: "query-ip 被拒绝"}
	msg := e.Error()
	if !strings.Contains(msg, "Shutdown") {
		t.Errorf("错误信息缺少控制码名称: %q", msg)
	}
	if !strings.Contains(msg, "query-ip") {
		t.Errorf("错误信息缺少上下文: %q", msg)
	}
}

func TestControlErrorUnknownCode(t *testing.T) {
	e := &ControlError{Code: 200}
	if e.Retryable() {
		t.Error("未知控制码不应被判为可重试")
	}
	if !strings.Contains(e.Error(), "Unknown") {
		t.Errorf("未知码应显示为 Unknown: %q", e.Error())
	}
}

func TestRetryPolicyDelayGrowsAndCaps(t *testing.T) {
	policy := RetryPolicy{Attempts: 4, Base: 2 * time.Second, Max: 30 * time.Second}
	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{0, 0},
		{1, 2 * time.Second},
		{2, 4 * time.Second},
		{3, 8 * time.Second},
		{4, 16 * time.Second},
		{5, 30 * time.Second}, // 32 秒超过上限
		{9, 30 * time.Second},
		{40, 30 * time.Second}, // 移位溢出必须被挡住，不能变成 0
	}
	for _, c := range cases {
		if got := policy.delay(c.attempt); got != c.want {
			t.Errorf("delay(%d) = %v，期望 %v", c.attempt, got, c.want)
		}
	}
}

func TestRetryableClassifiesControlErrors(t *testing.T) {
	if retryable(&ControlError{Code: ControlShutdown}) {
		t.Error("Shutdown 不应被判为可重试")
	}
	if !retryable(&ControlError{Code: ControlIPBusy}) {
		t.Error("IpBusy 应被判为可重试")
	}
	// 普通网络错误是暂时性的，值得重试。
	if !retryable(errors.New("connection reset")) {
		t.Error("普通错误应被判为可重试")
	}
}
