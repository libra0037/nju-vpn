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
