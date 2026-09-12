package service

import (
	"bytes"
	"errors"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/config"
	"github.com/libra0037/nju-vpn/internal/ipc"
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

	var buf lockedBuffer
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

// TestCredentialsNeverLogged 是凭据不入日志的完整回归（REVIEW C3）。
//
// 覆盖范围比 TestPasswordNeverLogged 大：口令由 `njuvpn start` 从 stdin 读入后
// 会以 base64 的形式经 IPC 报文传进来，报文行同样不能出现在日志里；
// TwfID、CSRF 码与 TOTP 密钥也一样。有人在服务进程里加一行 log.Printf(req)
// 或 log.Printf(password) 时，这条测试会失败。
func TestCredentialsNeverLogged(t *testing.T) {
	const password = "S3cr3t Pa55w0rd" // 含空格：口令要经 base64 才能过行协议
	const totpSecret = "JBSWY3DPEHPK3PXP"

	h := newHarnessWith(t, func(cfg *config.Config) {
		cfg.Password = "" // 口令只从本次请求带进来
		cfg.TOTPSecret = totpSecret
	})

	var buf lockedBuffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)

	endpoint, done := serve(t, h)
	defer closeServer(t, h, done)

	resp := request(t, endpoint, ipc.Request{
		Command: ipc.CmdStart,
		Args:    []string{ipc.EncodeSecret(password)},
	})
	if resp.Code != ipc.CodeOK {
		t.Fatalf("start 失败: %d %s", resp.Code, resp.Message)
	}
	waitState(t, h.svc, StateUp, 3*time.Second)

	logs := buf.String()
	// 后两个值来自假 portal 的固定响应：日志里只该出现脱敏后的前缀。
	for _, secret := range []struct{ name, value string }{
		{"口令原文", password},
		{"口令的 base64 形式", ipc.EncodeSecret(password)},
		{"TOTP 密钥", totpSecret},
		{"完整 TwfID", "fedcba9876543210"},
		{"登录页 TwfID", "0123456789abcdef"},
		{"CSRF 码", "csrftoken"},
	} {
		if strings.Contains(logs, secret.value) {
			t.Errorf("日志里出现了%s（%q）", secret.name, secret.value)
		}
	}
}

// lockedBuffer 是带锁的日志缓冲。
//
// 隧道协程等后台 goroutine 会在测试读日志的同时继续写，bytes.Buffer 本身
// 不是并发安全的（-race 下会直接失败）。
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
