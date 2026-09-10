package service

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"njuvpn/internal/config"
	"njuvpn/internal/vpn"
	"njuvpn/internal/vpntest"
)

// harness 装一套假的 portal 与假隧道，用来在没有校园网的情况下
// 驱动完整的服务生命周期。
type harness struct {
	svc    *Service
	portal *vpntest.Portal
	tunnel *vpntest.Tunnel
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	portal := vpntest.NewPortal()
	tunnel := vpntest.NewTunnel()

	portal.On("/por/login_auth.csp", vpntest.Response{Body: vpntest.LoginAuthPage()})
	portal.On("/por/login_psw.csp", vpntest.Response{
		Body: `<Auth><Result>1</Result><NextAuth>-1</NextAuth><TwfID>fedcba9876543210</TwfID></Auth>`,
	})
	portal.On("/por/logout.csp", vpntest.Response{
		Body: `<Auth><Message><![CDATA[logout user success]]></Message></Auth>`,
	})

	cfg := &config.Config{
		Server:    "vpn.example.edu",
		Port:      443,
		Username:  "u",
		Password:  "p",
		MTU:       1320,
		WireGuard: config.WireGuard{PeerAddress: "10.66.66.2"},
	}

	svc := New(cfg)
	svc.SetClientFactory(func(*config.Config) (*vpn.Client, error) {
		return vpn.New(vpn.Options{
			Server:    cfg.ServerAddr(),
			HTTP:      portal.HTTPClient(),
			PortalTLS: tunnel.Dial,
			TunnelTLS: tunnel.Dial,
			Timeouts:  vpn.Timeouts{HTTP: 5 * time.Second, Handshake: 5 * time.Second},
		}), nil
	})
	t.Cleanup(svc.Close)

	return &harness{svc: svc, portal: portal, tunnel: tunnel}
}

// waitState 等待服务进入某个状态。
func waitState(t *testing.T, svc *Service, want State, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if svc.Status().State == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("等待状态 %s 超时，当前 %s（%s）", want, svc.Status().State, svc.Status().Detail)
}

// reportTunnelExit 通过 actor 上报一次隧道协程退出，等同于真实路径。
func reportTunnelExit(t *testing.T, svc *Service, gen uint64, err error) {
	t.Helper()
	reply := make(chan error, 1)
	select {
	case svc.cmds <- &command{kind: cmdTunnelDown, gen: gen, err: err, reply: reply}:
	case <-time.After(time.Second):
		t.Fatal("命令通道阻塞")
	}
	select {
	case <-reply:
	case <-time.After(3 * time.Second):
		t.Fatal("等待 actor 处理超时")
	}
}

// 回归（功能不可用）：短信验证模式下，njuvpn auth <code> 提交的验证码
// 必须真的送到服务端，而不是被整条链路丢掉。
func TestAuthSubmitsCodeToServer(t *testing.T) {
	h := newHarness(t)
	h.portal.Set("/por/login_psw.csp", vpntest.Response{
		Body: `<Auth><Result>1</Result><NextAuth>2</NextAuth><NextService>auth/sms</NextService></Auth>`,
	})
	h.portal.Set("/por/login_sms.csp", vpntest.Response{
		Body: `<Auth><ErrorCode>1</ErrorCode><USER_PHONE>****</USER_PHONE><SmsSendInterval>178</SmsSendInterval></Auth>`,
	})
	h.portal.Set("/por/login_sms1.csp", vpntest.Response{
		Body: `<Auth>Auth sms suc</Auth><TwfID>aabbccddeeff0011</TwfID>`,
	})

	if err := h.svc.Start(); !errors.Is(err, ErrAuthRequired) {
		t.Fatalf("Start 应停在等待验证码，实际 %v", err)
	}
	if st := h.svc.Status().State; st != StateAuthPending {
		t.Fatalf("状态应为 auth_pending，实际 %s", st)
	}

	if err := h.svc.Auth("123456"); err != nil {
		t.Fatalf("提交验证码失败: %v", err)
	}
	waitState(t, h.svc, StateUp, 3*time.Second)

	form := h.portal.LastForm("/por/login_sms1.csp")
	if form == nil {
		t.Fatal("验证码没有提交到服务端")
	}
	if got := form.Get("svpn_inputsms"); got != "123456" {
		t.Errorf("提交的验证码 = %q", got)
	}
}

// 回归：Auth 成功后必须记住新的 TwfID，否则登出用的是过期标识，
// 服务端会话不会被释放。
func TestAuthUpdatesSessionIDUsedForLogout(t *testing.T) {
	h := newHarness(t)
	h.portal.Set("/por/login_psw.csp", vpntest.Response{
		Body: `<Auth><Result>1</Result><NextAuth>2</NextAuth><NextService>auth/sms</NextService></Auth>`,
	})
	h.portal.Set("/por/login_sms.csp", vpntest.Response{
		Body: `<Auth><ErrorCode>1</ErrorCode><USER_PHONE>****</USER_PHONE></Auth>`,
	})
	h.portal.Set("/por/login_sms1.csp", vpntest.Response{
		Body: `<Auth>Auth sms suc</Auth><TwfID>aabbccddeeff0011</TwfID>`,
	})

	if err := h.svc.Start(); !errors.Is(err, ErrAuthRequired) {
		t.Fatalf("Start 应停在等待验证码，实际 %v", err)
	}
	if err := h.svc.Auth("123456"); err != nil {
		t.Fatalf("提交验证码失败: %v", err)
	}
	waitState(t, h.svc, StateUp, 3*time.Second)

	if err := h.svc.Stop(); err != nil {
		t.Fatalf("Stop 失败: %v", err)
	}

	cookie := ""
	for _, r := range h.portal.Requests() {
		if r.Path == "/por/logout.csp" {
			cookie = r.Cookie
		}
	}
	if cookie == "" {
		t.Fatal("没有发出登出请求")
	}
	if cookie != "TWFID=aabbccddeeff0011" {
		t.Errorf("登出用的是过期会话: %q", cookie)
	}
}

// 验证码错误时保持 auth_pending，用户可以再输一次。
func TestAuthWrongCodeKeepsPendingState(t *testing.T) {
	h := newHarness(t)
	h.portal.Set("/por/login_psw.csp", vpntest.Response{
		Body: `<Auth><Result>1</Result><NextAuth>2</NextAuth><NextService>auth/sms</NextService></Auth>`,
	})
	h.portal.Set("/por/login_sms.csp", vpntest.Response{
		Body: `<Auth><ErrorCode>1</ErrorCode><USER_PHONE>****</USER_PHONE></Auth>`,
	})
	h.portal.Set("/por/login_sms1.csp", vpntest.Response{
		Body: `<Auth>Auth sms failed. invalid code</Auth>`,
	})

	if err := h.svc.Start(); !errors.Is(err, ErrAuthRequired) {
		t.Fatalf("Start 应停在等待验证码，实际 %v", err)
	}
	err := h.svc.Auth("000000")
	if err == nil {
		t.Fatal("验证码错误必须返回错误")
	}
	if !vpn.IsAuthCodeError(err) {
		t.Errorf("应被识别为验证码输入错误: %v", err)
	}
	if st := h.svc.Status().State; st != StateAuthPending {
		t.Errorf("状态应保持 auth_pending，实际 %s", st)
	}
}

// 回归：旧隧道协程退出后把刚建立的新会话一起拆掉。
func TestStaleTunnelExitIsIgnored(t *testing.T) {
	h := newHarness(t)
	if err := h.svc.Start(); err != nil {
		t.Fatalf("Start 失败: %v", err)
	}
	waitState(t, h.svc, StateUp, 3*time.Second)

	gen := h.svc.gen
	reportTunnelExit(t, h.svc, gen-1, errors.New("上一代协程退出"))

	if st := h.svc.Status().State; st != StateUp {
		t.Errorf("过期协程不应影响当前会话，状态 = %s", st)
	}
	if n := h.portal.Count("/por/logout.csp"); n != 0 {
		t.Errorf("过期退出报告不该触发登出（%d 次）", n)
	}
}

// 当前代次的隧道断开必须收敛到 error 并释放资源。
func TestCurrentTunnelExitTransitionsToError(t *testing.T) {
	h := newHarness(t)
	if err := h.svc.Start(); err != nil {
		t.Fatalf("Start 失败: %v", err)
	}
	waitState(t, h.svc, StateUp, 3*time.Second)

	reportTunnelExit(t, h.svc, h.svc.gen, errors.New("模拟断开"))

	if st := h.svc.Status().State; st != StateError {
		t.Errorf("状态应为 error，实际 %s", st)
	}
	if ip := h.svc.Status().PeerIP; ip != "" {
		t.Errorf("error 状态不应保留 peer 地址: %q", ip)
	}
	if n := h.portal.Count("/por/logout.csp"); n != 1 {
		t.Errorf("隧道断开应释放服务端会话，登出次数 = %d", n)
	}
}

// 回归：Start 全程持锁做网络 I/O 时，进程退出路径的登出会被永久阻塞。
// 现在 Close 必须能打断进行中的操作并完成收尾。
func TestCloseInterruptsLongOperation(t *testing.T) {
	h := newHarness(t)
	blocked := make(chan struct{})
	h.svc.SetClientFactory(func(cfg *config.Config) (*vpn.Client, error) {
		return vpn.New(vpn.Options{
			Server:    cfg.ServerAddr(),
			HTTP:      &http.Client{Transport: blockingTransport{unblock: blocked}},
			PortalTLS: h.tunnel.Dial,
			TunnelTLS: h.tunnel.Dial,
		}), nil
	})

	go func() { _ = h.svc.Start() }()
	waitState(t, h.svc, StateLoggingIn, 2*time.Second)

	done := make(chan struct{})
	go func() {
		h.svc.Close()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close 被进行中的网络 I/O 阻塞")
	}
	close(blocked)
}

// 回归：任何一处 panic 都不该带走整个进程——服务端的会话还开着。
func TestPanicInOperationIsContained(t *testing.T) {
	h := newHarness(t)
	h.svc.SetClientFactory(func(cfg *config.Config) (*vpn.Client, error) {
		return vpn.New(vpn.Options{
			Server:    cfg.ServerAddr(),
			HTTP:      &http.Client{Transport: panicTransport{}},
			PortalTLS: h.tunnel.Dial,
			TunnelTLS: h.tunnel.Dial,
		}), nil
	})

	err := h.svc.Start()
	if err == nil {
		t.Fatal("内部错误必须返回错误")
	}
	if st := h.svc.Status().State; st != StateError {
		t.Errorf("panic 后状态应为 error，实际 %s", st)
	}

	// 服务必须还活着：后续命令继续可用。
	if err := h.svc.Stop(); err != nil && !errors.Is(err, ErrNotRunning) {
		t.Errorf("panic 后服务不可用: %v", err)
	}
}

// 状态收敛：stop 之后地址信息必须清掉，不能继续对外展示。
func TestStopClearsAddresses(t *testing.T) {
	h := newHarness(t)
	if err := h.svc.Start(); err != nil {
		t.Fatalf("Start 失败: %v", err)
	}
	waitState(t, h.svc, StateUp, 3*time.Second)

	if err := h.svc.Stop(); err != nil {
		t.Fatalf("Stop 失败: %v", err)
	}
	st := h.svc.Status()
	if st.State != StateIdle {
		t.Errorf("状态应为 idle，实际 %s", st.State)
	}
	if st.PeerIP != "" || st.ClientIP != "" {
		t.Errorf("idle 状态不应保留地址: peer=%q client=%q", st.PeerIP, st.ClientIP)
	}
}

// 重复 Stop 应返回 ErrNotRunning，而不是报成服务端故障。
func TestStopWhenIdle(t *testing.T) {
	h := newHarness(t)
	if err := h.svc.Stop(); !errors.Is(err, ErrNotRunning) {
		t.Errorf("空闲时 Stop 应返回 ErrNotRunning，实际 %v", err)
	}
}

// 退出路径必须尝试登出，否则服务端会留下占名额的会话。
func TestCloseLogsOutOnce(t *testing.T) {
	h := newHarness(t)
	if err := h.svc.Start(); err != nil {
		t.Fatalf("Start 失败: %v", err)
	}
	waitState(t, h.svc, StateUp, 3*time.Second)

	h.svc.Close()
	h.svc.Close()

	if n := h.portal.Count("/por/logout.csp"); n != 1 {
		t.Errorf("登出次数 = %d，期望 1", n)
	}
}

// Status 不经过 actor，长操作期间也必须立即可用。
func TestStatusNeverBlocksDuringLongOperation(t *testing.T) {
	h := newHarness(t)
	blocked := make(chan struct{})
	h.svc.SetClientFactory(func(cfg *config.Config) (*vpn.Client, error) {
		return vpn.New(vpn.Options{
			Server:    cfg.ServerAddr(),
			HTTP:      &http.Client{Transport: blockingTransport{unblock: blocked}},
			PortalTLS: h.tunnel.Dial,
			TunnelTLS: h.tunnel.Dial,
		}), nil
	})
	go func() { _ = h.svc.Start() }()
	waitState(t, h.svc, StateLoggingIn, 2*time.Second)

	done := make(chan Status, 1)
	go func() { done <- h.svc.Status() }()
	select {
	case st := <-done:
		if st.State != StateLoggingIn {
			t.Errorf("状态 = %s，期望 logging_in", st.State)
		}
	case <-time.After(time.Second):
		t.Fatal("Status 被长操作阻塞")
	}
	close(blocked)
}

// 命令在服务退出后必须立刻返回，不能永久挂住调用方。
func TestCallAfterCloseReturnsError(t *testing.T) {
	h := newHarness(t)
	h.svc.Close()

	done := make(chan error, 1)
	go func() { done <- h.svc.Start() }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrShuttingDown) {
			t.Errorf("退出后调用应返回 ErrShuttingDown，实际 %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("退出后调用被挂住")
	}
}

// blockingTransport 一直不返回，直到被放开或请求上下文被取消。
type blockingTransport struct {
	unblock chan struct{}
}

func (b blockingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	select {
	case <-b.unblock:
		return nil, errors.New("测试：连接被放开")
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
}

// panicTransport 在往返里 panic，用来验证 actor 的 panic 边界。
type panicTransport struct{}

func (panicTransport) RoundTrip(*http.Request) (*http.Response, error) {
	panic("测试用的内部错误")
}
