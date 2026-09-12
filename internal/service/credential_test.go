package service

import (
	"bytes"
	"errors"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/config"
	"github.com/libra0037/nju-vpn/internal/vpntest"
)

// TestStartWithoutPasswordFails 验证没有可用口令时给出可操作的报错。
//
// 配置里允许不写口令（口令改由 njuvpn start 现问），但真到要登录时
// 一份口令都没有就必须停下来，而不是拿空口令去撞服务端。
func TestStartWithoutPasswordFails(t *testing.T) {
	h := newHarnessWith(t, func(cfg *config.Config) { cfg.Password = "" })

	err := h.svc.Start()
	if err == nil || !strings.Contains(err.Error(), "口令") {
		t.Fatalf("应提示缺少口令，实际 %v", err)
	}
	if st := h.svc.Status().State; st != StateError {
		t.Fatalf("状态应为 error，实际 %s", st)
	}
	if h.portal.LastForm("/por/login_auth.csp") != nil {
		t.Fatal("没有口令时不该发起登录")
	}
}

// TestStartWithPasswordLogsIn 验证随请求带来的口令真的用于登录。
func TestStartWithPasswordLogsIn(t *testing.T) {
	h := newHarnessWith(t, func(cfg *config.Config) { cfg.Password = "" })

	if err := h.svc.StartWithPassword("s3cr3t-pw"); err != nil && !errors.Is(err, ErrAuthRequired) {
		t.Fatalf("带上口令后应当能登录: %v", err)
	}
	form := h.portal.LastForm("/por/login_psw.csp")
	if form == nil {
		t.Fatal("口令没有用于登录")
	}
	if form.Get("svpn_password") == "" {
		t.Fatal("登录表单里没有口令字段")
	}
}

// TestPasswordNeverLogged 验证口令不出现在日志里。
//
// 这条曾经真的出过问题：旧实现把明文口令打进了日志。口令现在还可能
// 经本地套接字传进来，值不值得信任先放一边，至少它不能落在日志里。
func TestPasswordNeverLogged(t *testing.T) {
	const password = "S3cr3t-Pa55w0rd"

	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)

	h := newHarnessWith(t, func(cfg *config.Config) { cfg.Password = "" })
	if err := h.svc.StartWithPassword(password); err != nil && !errors.Is(err, ErrAuthRequired) {
		t.Fatalf("建立隧道失败: %v", err)
	}
	if strings.Contains(buf.String(), password) {
		t.Fatalf("日志里出现了口令明文:\n%s", buf.String())
	}
}

// TestSecondStartReusesPassword 验证同一进程内后续登录不必再问口令。
//
// 第一次 start 带回口令后，服务进程把它留在内存里：隧道断开后重新 start
// （不再带口令）时仍然能用。
func TestSecondStartReusesPassword(t *testing.T) {
	h := newHarnessWith(t, func(cfg *config.Config) { cfg.Password = "" })

	// 假 portal 的响应是按次消费的，两轮登录要各注册一遍。
	registerLogin := func() {
		h.portal.Set("/por/login_auth.csp", vpntest.Response{Body: vpntest.LoginAuthPage()})
		h.portal.Set("/por/login_psw.csp", vpntest.Response{
			Body: "<Auth><Result>1</Result><NextAuth>2</NextAuth><NextService>auth/sms</NextService></Auth>",
		})
		h.portal.Set("/por/login_sms.csp", vpntest.Response{
			Body: "<Auth><ErrorCode>1</ErrorCode><USER_PHONE>****</USER_PHONE><SmsSendInterval>178</SmsSendInterval></Auth>",
		})
		h.portal.Set("/por/login_sms1.csp", vpntest.Response{
			Body: "<Auth>Auth sms suc</Auth><TwfID>aabbccddeeff0011</TwfID>",
		})
	}

	registerLogin()
	if err := h.svc.StartWithPassword("s3cr3t-pw"); !errors.Is(err, ErrAuthRequired) {
		t.Fatalf("应停在等待验证码，实际 %v", err)
	}
	if err := h.svc.Auth("123456"); err != nil {
		t.Fatalf("提交验证码失败: %v", err)
	}
	waitState(t, h.svc, StateUp, 3*time.Second)

	// 停掉隧道后再来一次：这次不带口令，内存里那份应当还在。
	if err := h.svc.Stop(); err != nil {
		t.Fatalf("断开失败: %v", err)
	}
	registerLogin()
	if err := h.svc.Start(); err != nil && !errors.Is(err, ErrAuthRequired) {
		t.Fatalf("第二次 start 应当复用内存里的口令: %v", err)
	}
}
