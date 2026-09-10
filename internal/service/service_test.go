package service

import (
	"bytes"
	"errors"
	"log"
	"net"
	"strings"
	"testing"

	"njuvpn/internal/config"
	"njuvpn/internal/vpn"
)

// newTestService 构造一个登出必然失败的 Service，用于验证退出路径。
//
// 拨号函数直接返回错误而不是连不可达地址：某些环境下连接会被丢弃而非拒绝，
// 那样测试要等满登出超时（10 秒）。
func newTestService(t *testing.T) *Service {
	t.Helper()
	dialFn := func(network, address string) (net.Conn, error) {
		return nil, errors.New("测试用：拒绝拨号")
	}
	svc := New(&config.Config{Server: "127.0.0.1", Port: 1})
	svc.client = vpn.NewClient("127.0.0.1:1", dialFn)
	svc.twfID = "0123456789abcdef"
	return svc
}

func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)
	fn()
	return buf.String()
}

// 退出路径必须尝试通知服务端登出，否则服务端会留下占用名额的会话。
func TestCloseAttemptsLogout(t *testing.T) {
	svc := newTestService(t)

	got := captureLog(t, svc.Close)

	if !strings.Contains(got, "登出") {
		t.Errorf("Close 未尝试登出，日志: %q", got)
	}
	if svc.twfID != "" {
		t.Errorf("Close 后 twfID 未清空: %q", svc.twfID)
	}
}

// Probe 失败但已拿到 TWFID 时，也必须能登出。
//
// 这是真实踩过的坑：Start 里原先在 err != nil 之前不记录 res.TwfID，
// 于是 query-ip 失败（登录已成功）时 release 会跳过登出，
// 服务端累积未释放的会话，最终导致后续建隧道全被拒。
func TestFailAfterPartialProbeStillLogsOut(t *testing.T) {
	svc := newTestService(t)
	svc.state = newMachine()
	if err := svc.state.Transition(StateLoggingIn, "正在登录"); err != nil {
		t.Fatal(err)
	}

	// 模拟 Probe 的返回值：登录成功拿到 TWFID，但后续阶段失败。
	res := &vpn.ProbeResult{TwfID: "0123456789abcdef"}
	if res.TwfID != "" {
		svc.twfID = res.TwfID
	}

	got := captureLog(t, func() { svc.fail(errors.New("模拟建隧道失败")) })

	if !strings.Contains(got, "登出") {
		t.Errorf("部分失败路径未尝试登出，日志: %q", got)
	}
	if svc.state.Get().State != StateError {
		t.Errorf("状态应为 error，实际 %s", svc.state.Get().State)
	}
}

// Close 可重复调用，不应 panic。
func TestCloseIdempotent(t *testing.T) {
	svc := newTestService(t)
	captureLog(t, func() {
		svc.Close()
		svc.Close()
	})
}

// 没有会话时不应产生登出请求。
func TestCloseWithoutSession(t *testing.T) {
	svc := New(&config.Config{Server: "127.0.0.1", Port: 1})

	got := captureLog(t, svc.Close)

	if strings.Contains(got, "登出") {
		t.Errorf("无会话时不应尝试登出，日志: %q", got)
	}
}
