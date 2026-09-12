package service

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/vpntest"
)

// TestAuthPendingTimesOut 验证等验证码超时后自动登出。
//
// 用户在提示符前直接关掉终端时，进程会一直停在 auth_pending，学校侧那条
// "同一账号只允许一个客户端"的名额也跟着被占住（REVIEW R4）。
func TestAuthPendingTimesOut(t *testing.T) {
	old := authWaitTimeout
	authWaitTimeout = 100 * time.Millisecond
	t.Cleanup(func() { authWaitTimeout = old })

	h := newHarness(t)
	h.portal.Set("/por/login_psw.csp", vpntest.Response{
		Body: "<Auth><Result>1</Result><NextAuth>2</NextAuth><NextService>auth/sms</NextService></Auth>",
	})
	h.portal.Set("/por/login_sms.csp", vpntest.Response{
		Body: "<Auth><ErrorCode>1</ErrorCode><USER_PHONE>****</USER_PHONE><SmsSendInterval>178</SmsSendInterval></Auth>",
	})

	if err := h.svc.StartWithPassword("p"); !errors.Is(err, ErrAuthRequired) {
		t.Fatalf("Start 应停在等待验证码，实际 %v", err)
	}
	waitState(t, h.svc, StateAuthPending, time.Second)

	waitState(t, h.svc, StateError, 5*time.Second)
	if h.portal.Count("/por/logout.csp") == 0 {
		t.Fatal("超时后应当登出，否则服务端名额一直被占着")
	}
	if detail := h.svc.Status().Detail; !strings.Contains(detail, "njuvpn start") {
		t.Fatalf("超时说明里应给出恢复命令，实际 %q", detail)
	}
}

// TestAuthTimeoutCancelledWhenCodeSubmitted 验证按时输入验证码后计时器被取消。
//
// 少了这一步，用户建好隧道之后会被那条计时器再踢下线一次。
func TestAuthTimeoutCancelledWhenCodeSubmitted(t *testing.T) {
	old := authWaitTimeout
	authWaitTimeout = 300 * time.Millisecond
	t.Cleanup(func() { authWaitTimeout = old })

	h := newHarness(t)
	h.portal.Set("/por/login_psw.csp", vpntest.Response{
		Body: "<Auth><Result>1</Result><NextAuth>2</NextAuth><NextService>auth/sms</NextService></Auth>",
	})
	h.portal.Set("/por/login_sms.csp", vpntest.Response{
		Body: "<Auth><ErrorCode>1</ErrorCode><USER_PHONE>****</USER_PHONE><SmsSendInterval>178</SmsSendInterval></Auth>",
	})
	h.portal.Set("/por/login_sms1.csp", vpntest.Response{
		Body: "<Auth>Auth sms suc</Auth><TwfID>aabbccddeeff0011</TwfID>",
	})

	if err := h.svc.StartWithPassword("p"); !errors.Is(err, ErrAuthRequired) {
		t.Fatalf("Start 应停在等待验证码，实际 %v", err)
	}
	if err := h.svc.Auth("123456"); err != nil {
		t.Fatalf("提交验证码失败: %v", err)
	}
	waitState(t, h.svc, StateUp, 3*time.Second)

	// 越过原定的超时点：隧道必须还在。
	time.Sleep(600 * time.Millisecond)
	if st := h.svc.Status().State; st != StateUp {
		t.Fatalf("验证码已提交后计时器应当被取消，状态却是 %s（%s）", st, h.svc.Status().Detail)
	}
}

// 回归：上一轮的"等验证码超时"不许拆掉这一轮。
//
// 计时器可能已经触发、命令正排在队列里，而那一轮早就收场（用户重新
// start 了，或者验证码已经输对）。旧实现没有轮次概念，这条迟到的命令
// 会把新一轮的 auth_pending 直接收尾：用户刚收到短信，状态就变成
// "等待验证码超时，已登出"。
func TestStaleAuthTimeoutIsIgnored(t *testing.T) {
	h := newHarness(t)
	h.portal.Set("/por/login_psw.csp", vpntest.Response{
		Body: "<Auth><Result>1</Result><NextAuth>2</NextAuth><NextService>auth/sms</NextService></Auth>",
	})
	h.portal.Set("/por/login_sms.csp", vpntest.Response{
		Body: "<Auth><ErrorCode>1</ErrorCode><USER_PHONE>****</USER_PHONE><SmsSendInterval>178</SmsSendInterval></Auth>",
	})

	if err := h.svc.StartWithPassword("p"); !errors.Is(err, ErrAuthRequired) {
		t.Fatalf("Start 应停在等待验证码，实际 %v", err)
	}
	waitState(t, h.svc, StateAuthPending, time.Second)
	before := h.portal.Count("/por/logout.csp")

	// 模拟上一轮的迟到命令：轮次比当前小，走 actor 投进去。
	reply := make(chan error, 1)
	select {
	case h.svc.cmds <- &command{kind: cmdAuthTimeout, seq: h.svc.authSeq - 1, reply: reply}:
	case <-time.After(time.Second):
		t.Fatal("命令通道阻塞")
	}
	select {
	case <-reply:
	case <-time.After(3 * time.Second):
		t.Fatal("等待 actor 处理超时")
	}

	if st := h.svc.Status().State; st != StateAuthPending {
		t.Fatalf("过期命令不该改动状态，实际 %s（%s）", st, h.svc.Status().Detail)
	}
	if got := h.portal.Count("/por/logout.csp"); got != before {
		t.Fatal("过期命令不该触发登出：那一轮已经收场了")
	}
}
