package service

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"njuvpn/internal/config"
	"njuvpn/internal/vpn"
	"njuvpn/internal/vpntest"
	"njuvpn/internal/wireguard"
)

// harness 装一套假的 portal 与假隧道，用来在没有校园网的情况下
// 驱动完整的服务生命周期。
type harness struct {
	svc    *Service
	portal *vpntest.Portal
	tunnel *vpntest.Tunnel
	// lastOptions 是生产代码算出、测试再补过的构造参数。
	lastOptions vpn.Options
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
		Server:   "vpn.example.edu",
		Port:     443,
		Username: "u",
		Password: "p",
		MTU:      1320,
		WireGuard: config.WireGuard{
			PeerAddress: "10.66.66.2",
			// 承载层需要一个能用的私钥；这里现生成，端口取 0 让系统分配。
			PrivateKey: testPrivateKey(t),
			ListenPort: 0,
		},
	}

	svc := New(cfg)
	h := &harness{svc: svc, portal: portal, tunnel: tunnel}
	// 只补协议层内部的注入点；Server / DialAddr / Dial 由生产代码算，
	// 顺便记下来供 TestClientOptionsUseProductionWiring 断言。
	svc.SetClientOptions(func(opts *vpn.Options) {
		h.lastOptions = *opts
		opts.HTTP = portal.HTTPClient()
		opts.PortalTLS = tunnel.Dial
		opts.TunnelTLS = tunnel.Dial
		opts.Timeouts = vpn.Timeouts{HTTP: 5 * time.Second, Handshake: 5 * time.Second}
	})
	t.Cleanup(svc.Close)

	return h
}

// testPrivateKey 生成一个测试用的 WireGuard 私钥。
func testPrivateKey(t *testing.T) string {
	t.Helper()
	key, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key.String()
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
	h.svc.SetClientOptions(func(opts *vpn.Options) {
		opts.HTTP = &http.Client{Transport: blockingTransport{unblock: blocked}}
		opts.PortalTLS = h.tunnel.Dial
		opts.TunnelTLS = h.tunnel.Dial
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
	h.svc.SetClientOptions(func(opts *vpn.Options) {
		opts.HTTP = &http.Client{Transport: panicTransport{}}
		opts.PortalTLS = h.tunnel.Dial
		opts.TunnelTLS = h.tunnel.Dial
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
	h.svc.SetClientOptions(func(opts *vpn.Options) {
		opts.HTTP = &http.Client{Transport: blockingTransport{unblock: blocked}}
		opts.PortalTLS = h.tunnel.Dial
		opts.TunnelTLS = h.tunnel.Dial
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

// 回归（真机实测发现）：二次验证续用的就是 start 留下的那个会话，
// 但如果 auth 建好新会话对象后去"释放上一个会话"，就会用同一个 TwfID
// 把正在续用的会话登出。
//
// 真机表现：auth 返回成功、状态一度是 up，紧接着上行流握手被服务端以
// Shutdown(8) 拒绝——因为会话刚被自己杀掉。这里断言续用期间**一次登出
// 都不能发生**。
func TestAuthContinuationDoesNotLogoutSharedSession(t *testing.T) {
	h := newHarness(t)
	// 服务端不返回新 TwfID，即续用登录时的那个。
	h.portal.Set("/por/login_psw.csp", vpntest.Response{
		Body: `<Auth><Result>1</Result><NextAuth>2</NextAuth><NextService>auth/sms</NextService></Auth>`,
	})
	h.portal.Set("/por/login_sms.csp", vpntest.Response{
		Body: `<Auth><ErrorCode>1</ErrorCode><USER_PHONE>****</USER_PHONE></Auth>`,
	})
	h.portal.Set("/por/login_sms1.csp", vpntest.Response{
		Body: `<Auth>Auth sms suc</Auth>`,
	})

	if err := h.svc.Start(); !errors.Is(err, ErrAuthRequired) {
		t.Fatalf("Start 应停在等待验证码，实际 %v", err)
	}
	if n := h.portal.Count("/por/logout.csp"); n != 0 {
		t.Fatalf("还在等验证码就登出了 %d 次", n)
	}

	if err := h.svc.Auth("123456"); err != nil {
		t.Fatalf("提交验证码失败: %v", err)
	}
	waitState(t, h.svc, StateUp, 3*time.Second)

	if n := h.portal.Count("/por/logout.csp"); n != 0 {
		t.Errorf("续用会话期间发生了 %d 次登出——会把正在使用的会话杀掉", n)
	}
	// 隧道必须还能用：下行流握手不该被拒。
	if err := h.svc.session.CheckTunnel(context.Background()); err != nil {
		t.Errorf("续用后隧道不可用: %v", err)
	}
}

// 回归：attach 遇到共用同一 TwfID 的会话时只能释放本地资源。
func TestAttachSameSessionDoesNotLogout(t *testing.T) {
	h := newHarness(t)
	if err := h.svc.Start(); err != nil {
		t.Fatalf("Start 失败: %v", err)
	}
	waitState(t, h.svc, StateUp, 3*time.Second)

	prev := h.svc.session
	// 造一个新会话对象，但携带同一个 TwfID。
	same, err := h.svc.client.Connect(context.Background(), vpn.ConnectOptions{
		Username: "u",
		Password: "p",
		TwfID:    prev.TwfID(),
		Trace:    &vpn.Trace{},
	})
	if err != nil {
		t.Fatalf("续用失败: %v", err)
	}
	defer same.Close(context.Background())

	h.svc.attach(same)

	if n := h.portal.Count("/por/logout.csp"); n != 0 {
		t.Errorf("共用 TwfID 的会话被登出了 %d 次", n)
	}
}

// 服务端说"没有这个会话"时，释放资源不该报成错误。
func TestTeardownToleratesMissingServerSession(t *testing.T) {
	h := newHarness(t)
	if err := h.svc.Start(); err != nil {
		t.Fatalf("Start 失败: %v", err)
	}
	waitState(t, h.svc, StateUp, 3*time.Second)

	// 之后再有人登出同一个会话，服务端会回 logout user failed。
	h.portal.Set("/por/logout.csp", vpntest.Response{
		Body: `<Auth><Message><![CDATA[logout user failed]]></Message></Auth>`,
	})

	if err := h.svc.Stop(); err != nil {
		t.Errorf("会话已不存在时 Stop 不该报错: %v", err)
	}
	if st := h.svc.Status().State; st != StateIdle {
		t.Errorf("状态应为 idle，实际 %s", st)
	}
}

// 回归：peer 更新必须能写回配置文件，且不需要重建隧道。
func TestSetPeerPersistsAndApplies(t *testing.T) {
	h := newHarness(t)
	h.svc.cfg.SetSourcePath(filepath.Join(t.TempDir(), "config.yaml"))
	// 先写出一份能被解析的配置文件。
	if err := os.WriteFile(h.svc.cfg.SourcePath(), []byte(
		"server: vpn.example.edu\nusername: u\npassword: p\nwireguard:\n  listen_port: 51820\n  peer_public_key: \"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.svc.cfg.WireGuard.PeerPublicKey = ""

	peerPriv, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	peerPub, err := peerPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	// 隧道没建立时也要接受：只写回配置。
	if err := h.svc.SetPeer(peerPub.String()); err != nil {
		t.Fatalf("设置 peer 失败: %v", err)
	}
	if got := h.svc.cfg.WireGuard.PeerPublicKey; got != peerPub.String() {
		t.Errorf("内存里的配置没更新: %q", got)
	}

	raw, err := os.ReadFile(h.svc.cfg.SourcePath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "peer_public_key: "+peerPub.String()) {
		t.Errorf("配置文件没写回:\n%s", raw)
	}

	// 隧道建立后，更新应当立刻作用到设备上，且 peer 数量仍为 1。
	if err := h.svc.Start(); err != nil {
		t.Fatalf("Start 失败: %v", err)
	}
	waitState(t, h.svc, StateUp, 3*time.Second)

	second, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	secondPub, err := second.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := h.svc.SetPeer(secondPub.String()); err != nil {
		t.Fatalf("热更新 peer 失败: %v", err)
	}
	stats, err := h.svc.device.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 1 {
		t.Errorf("peer 数量 = %d，期望 1（replace_peers 应清掉旧的）", len(stats))
	}
	// 隧道本身不该被影响。
	if st := h.svc.Status().State; st != StateUp {
		t.Errorf("更新 peer 后状态变成了 %s", st)
	}
}

// 非法公钥必须被拒绝，且不能动已有配置。
func TestSetPeerRejectsBadKey(t *testing.T) {
	h := newHarness(t)
	if err := h.svc.SetPeer("not-a-key"); err == nil {
		t.Error("非法公钥应被拒绝")
	}
	if err := h.svc.SetPeer(""); err == nil {
		t.Error("空公钥应被拒绝")
	}
}

// 回归（原 E5）：注入点以前是"整体替换 Client 的构造方式"，于是
// Server / DialAddr 这条生产接线从没进过测试——server_ip 是个必须用的
// 字段（校园内 DNS 解析不了域名），接错了也照样全绿。
func TestClientOptionsUseProductionWiring(t *testing.T) {
	h := newHarness(t)
	h.svc.cfg.ServerIP = "202.119.32.69"

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

	if got, want := h.lastOptions.Server, h.svc.cfg.ServerAddr(); got != want {
		t.Errorf("Server = %q，期望 %q", got, want)
	}
	if got, want := h.lastOptions.DialAddr, "202.119.32.69:443"; got != want {
		t.Errorf("DialAddr = %q，期望 %q（server_ip 必须生效）", got, want)
	}
	if h.lastOptions.Dial == nil {
		t.Error("Dial 没接上：出站路径会直接 panic")
	}
}

// 回归：隧道已经在跑时再敲一次 start，报的是"状态不允许"（IPC 层映射成 409），
// 而不是 500 —— 脚本据此区分"用法问题"和"服务端故障"。
func TestStartOnRunningTunnelReportsBadState(t *testing.T) {
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
	if err := h.svc.Auth("123456"); err != nil {
		t.Fatalf("提交验证码失败: %v", err)
	}
	waitState(t, h.svc, StateUp, 3*time.Second)

	err := h.svc.Start()
	if !errors.Is(err, ErrBadState) {
		t.Fatalf("隧道已在运行时 start 应返回 ErrBadState，实际 %v", err)
	}
	// 已经在跑的隧道不该被这次调用拆掉。
	if st := h.svc.Status().State; st != StateUp {
		t.Errorf("状态被改成了 %s", st)
	}
}

// 回归：退出期间挤进 actor 的命令必须被拒绝。
//
// Close 已经走过登出，此时若还执行 start，就会新建一条没人管的会话，
// 而服务端同一账号只允许一个客户端——下次启动会直接建不上隧道。
func TestDispatchRejectsCommandAfterClose(t *testing.T) {
	h := newHarness(t)
	h.svc.Close()

	// 模拟"关闭瞬间 actor 恰好取到了一条排队中的命令"。
	cmd := &command{kind: cmdStart, reply: make(chan error, 1)}
	h.svc.dispatch(cmd)

	select {
	case err := <-cmd.reply:
		if !errors.Is(err, ErrShuttingDown) {
			t.Errorf("关闭后的命令应被拒绝，得到 %v", err)
		}
	default:
		t.Fatal("关闭后的命令没有收到回复")
	}
}
