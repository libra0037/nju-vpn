package service

import (
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/config"
	"github.com/libra0037/nju-vpn/internal/ipc"
	"github.com/libra0037/nju-vpn/internal/wireguard"
	"github.com/libra0037/nju-vpn/internal/ztna"
	"github.com/libra0037/nju-vpn/internal/ztnatest"
)

const (
	testUser = "600000000000"
	testPass = "secret"
	testCode = "123456"
	testVIP  = "172.16.0.9"
)

func newFakeServer(t *testing.T, opts ztnatest.Options) *ztnatest.Server {
	t.Helper()
	if opts.Username == "" {
		opts.Username = testUser
	}
	if opts.Password == "" {
		opts.Password = testPass
	}
	if opts.Phone == "" {
		opts.Phone = "138****0000"
	}
	srv, err := ztnatest.New(opts)
	if err != nil {
		t.Fatalf("启动假服务端失败: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv
}

func newTestConfig(t *testing.T, srv *ztnatest.Server) *config.Config {
	t.Helper()
	key, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Server:   "vpn.test",
		ServerIP: host,
		Port:     port,
		Username: testUser,
		Password: testPass,
		DeviceID: "device-test-1",
		MTU:      1320,
		WireGuard: config.WireGuard{
			ListenPort:  0,
			PrivateKey:  key.String(),
			PeerAddress: "10.66.66.2",
		},
		Log: config.Log{Level: "info"},
	}
	cfg.SetSourcePath(filepath.Join(t.TempDir(), "config.yaml"))
	return cfg
}

func newTestService(t *testing.T, srv *ztnatest.Server, cfg *config.Config) *Service {
	t.Helper()
	svc, err := New(cfg)
	if err != nil {
		t.Fatalf("启动服务对象失败: %v", err)
	}
	svc.SetDialer(srv.Dial)
	t.Cleanup(svc.Close)
	return svc
}

func waitState(t *testing.T, svc *Service, want State) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if svc.Status().State == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("状态停在 %s（%s），期望 %s", svc.Status().State, svc.Status().Detail, want)
}

func TestStartWithSecondFactorThenTrustAndStop(t *testing.T) {
	srv := newFakeServer(t, ztnatest.Options{RequireSMS: true, VerifyCode: testCode})
	svc := newTestService(t, srv, newTestConfig(t, srv))

	err := svc.Start(false, testPass)
	if !errors.Is(err, ErrAuthRequired) {
		t.Fatalf("应停在等验证码这一步，得到 %v", err)
	}
	st := svc.Status()
	if st.State != StateAuthPending {
		t.Fatalf("状态 = %s，期望 auth_pending", st.State)
	}
	if !strings.Contains(st.Detail, "138****0000") {
		t.Errorf("状态里应带上脱敏手机号，得到 %q", st.Detail)
	}
	if srv.SMSSends() != 1 {
		t.Errorf("发码请求 %d 次，期望 1 次", srv.SMSSends())
	}

	// 验证码错误：留在等待状态，让用户再输一次。
	if err := svc.Auth("000000"); err == nil {
		t.Fatal("错误的验证码应被拒绝")
	} else if _, ok := ztna.AsRejected(err); !ok {
		t.Errorf("验证码错误应报成被拒绝，得到 %v", err)
	}
	if got := svc.Status().State; got != StateAuthPending {
		t.Errorf("验证码错误后状态 = %s，期望仍停在 auth_pending", got)
	}

	if err := svc.Auth(testCode); err != nil {
		t.Fatalf("正确的验证码应通过: %v", err)
	}
	st = svc.Status()
	if st.State != StateUp {
		t.Fatalf("状态 = %s，期望 up", st.State)
	}
	if st.ClientIP != testVIP || st.PeerIP != "10.66.66.2" {
		t.Errorf("地址 = %s / %s，期望 %s / 10.66.66.2", st.ClientIP, st.PeerIP, testVIP)
	}

	// 隧道在跑时，授信终端操作复用当前会话：不重新登录、不重建隧道。
	if err := svc.Trust(""); err != nil {
		t.Fatalf("绑定授信终端失败: %v", err)
	}
	if got := srv.Trusted(); len(got) != 1 || got[0] != "self-1" {
		t.Errorf("服务端授信终端 = %v，期望 [self-1]", got)
	}
	if srv.Tunnels() != 1 {
		t.Errorf("隧道连接数 = %d，期望 1（复用会话，不该重建）", srv.Tunnels())
	}
	if !strings.Contains(svc.Status().Detail, "已确认为授信终端") {
		t.Errorf("状态说明 = %q，期望带上绑定结果", svc.Status().Detail)
	}

	if err := svc.Untrust("", true); err != nil {
		t.Fatalf("解除全部授信失败: %v", err)
	}
	if got := srv.Trusted(); len(got) != 0 {
		t.Errorf("解除全部之后仍有授信终端: %v", got)
	}
	if srv.Tunnels() != 1 {
		t.Errorf("解除授信不该重建隧道，隧道连接数 = %d", srv.Tunnels())
	}

	if err := svc.Stop(); err != nil {
		t.Fatalf("断开失败: %v", err)
	}
	if svc.Status().State != StateIdle {
		t.Errorf("断开后状态 = %s，期望 idle", svc.Status().State)
	}
	if n := srv.LogoutCount(); n != 1 {
		t.Errorf("登出次数 = %d，期望 1", n)
	}
	if err := svc.Stop(); !errors.Is(err, ErrNotRunning) {
		t.Errorf("重复断开应报未运行，得到 %v", err)
	}
}

func TestStartWithoutPasswordFails(t *testing.T) {
	srv := newFakeServer(t, ztnatest.Options{})
	cfg := newTestConfig(t, srv)
	cfg.Password = ""
	svc := newTestService(t, srv, cfg)

	err := svc.Start(false, "")
	if err == nil || !strings.Contains(err.Error(), "没有可用的口令") {
		t.Fatalf("缺口令时应给出可操作的错误，得到 %v", err)
	}
	if svc.Status().State != StateError {
		t.Errorf("状态 = %s，期望 error", svc.Status().State)
	}

	// 口令随本次请求带进来就该成功。
	if err := svc.Start(false, testPass); err != nil {
		t.Fatalf("带口令的启动应成功: %v", err)
	}
	if svc.Status().State != StateUp {
		t.Errorf("状态 = %s，期望 up", svc.Status().State)
	}
}

func TestTrustAndUntrustLogInOnlyWhenNeeded(t *testing.T) {
	srv := newFakeServer(t, ztnatest.Options{})
	svc := newTestService(t, srv, newTestConfig(t, srv))

	// 隧道没在跑：为这次操作单独登录一次，结束后登出。
	if err := svc.Trust(""); err != nil {
		t.Fatalf("绑定授信终端失败: %v", err)
	}
	if got := srv.Trusted(); len(got) != 1 {
		t.Errorf("服务端授信终端 = %v", got)
	}
	if srv.Tunnels() != 0 {
		t.Errorf("授信终端操作不该建立隧道，收到 %d 条", srv.Tunnels())
	}
	if n := srv.LogoutCount(); n != 1 {
		t.Errorf("登出次数 = %d，期望 1（这次登录只为操作）", n)
	}
	if got := svc.Status().State; got != StateIdle {
		t.Errorf("状态 = %s，期望回到 idle", got)
	}

	if err := svc.Untrust("", false); err != nil {
		t.Fatalf("解除授信失败: %v", err)
	}
	if got := srv.Trusted(); len(got) != 0 {
		t.Errorf("解除之后仍有授信终端: %v", got)
	}
	if n := srv.LogoutCount(); n != 2 {
		t.Errorf("登出次数 = %d，期望 2", n)
	}
}

func TestAuthWaitTimeoutReleasesSession(t *testing.T) {
	srv := newFakeServer(t, ztnatest.Options{RequireSMS: true, VerifyCode: testCode})
	svc := newTestService(t, srv, newTestConfig(t, srv))

	old := authWaitTimeout
	authWaitTimeout = 300 * time.Millisecond
	t.Cleanup(func() { authWaitTimeout = old })

	if err := svc.Start(false, testPass); !errors.Is(err, ErrAuthRequired) {
		t.Fatalf("应停在等验证码这一步，得到 %v", err)
	}
	waitState(t, svc, StateError)
	if !strings.Contains(svc.Status().Detail, "等待验证码超过") {
		t.Errorf("状态说明 = %q，期望说明超时原因", svc.Status().Detail)
	}
	// 超时必须登出：否则服务端那条唯一的名额会被一直占着。
	if n := srv.LogoutCount(); n != 1 {
		t.Errorf("登出次数 = %d，期望 1", n)
	}
}

func TestTunnelReconnectKeepsSession(t *testing.T) {
	srv := newFakeServer(t, ztnatest.Options{})
	svc := newTestService(t, srv, newTestConfig(t, srv))

	if err := svc.Start(false, testPass); err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	if srv.Tunnels() != 1 {
		t.Fatalf("隧道连接数 = %d，期望 1", srv.Tunnels())
	}

	// 掐断隧道：应自己重连，不重新登录（重登会花一条短信，也会抢名额）。
	srv.CloseTunnel()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && srv.Tunnels() < 2 {
		time.Sleep(20 * time.Millisecond)
	}
	if srv.Tunnels() < 2 {
		t.Fatalf("隧道没有重连（连接数仍是 %d）", srv.Tunnels())
	}
	if n := srv.LogoutCount(); n != 0 {
		t.Errorf("重连不该登出，登出次数 = %d", n)
	}
	waitState(t, svc, StateUp)
	if svc.Status().Retrying {
		t.Error("重连成功后不该还标着正在重连")
	}
}

func TestTunnelGivingUpLandsInError(t *testing.T) {
	srv := newFakeServer(t, ztnatest.Options{})
	svc := newTestService(t, srv, newTestConfig(t, srv))

	if err := svc.Start(false, testPass); err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	// 关掉假服务端再掐断隧道：重连必然失败，状态要收敛成 error。
	srv.Close()
	srv.CloseTunnel()
	waitState(t, svc, StateError)
	if !strings.Contains(svc.Status().Detail, "隧道已断开") {
		t.Errorf("状态说明 = %q，期望说明隧道已断开", svc.Status().Detail)
	}
}

func TestServerDispatchContract(t *testing.T) {
	srv := newFakeServer(t, ztnatest.Options{})
	svc := newTestService(t, srv, newTestConfig(t, srv))
	s := &Server{svc: svc, closing: make(chan struct{}), quit: make(chan struct{})}

	if resp := s.dispatch(ipc.Request{Command: "nope"}); resp.Code != ipc.CodeBadRequest {
		t.Errorf("未知命令的状态码 = %d，期望 400", resp.Code)
	}
	if resp := s.dispatch(ipc.Request{Command: ipc.CmdStart, Args: []string{"trust=maybe"}}); resp.Code != ipc.CodeBadRequest {
		t.Errorf("参数写错的状态码 = %d，期望 400", resp.Code)
	}
	if resp := s.dispatch(ipc.Request{Command: ipc.CmdAuth, Args: []string{"123456"}}); resp.Code != ipc.CodeRejected {
		t.Errorf("不需要验证码时提交验证码的状态码 = %d，期望 409", resp.Code)
	}
	if resp := s.dispatch(ipc.Request{Command: ipc.CmdState}); resp.Code != ipc.CodeOK || resp.Message != string(StateIdle) {
		t.Errorf("state = %d %q，期望 200 idle", resp.Code, resp.Message)
	}
	if resp := s.dispatch(ipc.Request{Command: ipc.CmdPing}); resp.Code != ipc.CodeOK || !strings.Contains(resp.Message, "pong") {
		t.Errorf("ping = %d %q", resp.Code, resp.Message)
	}

	resp := s.dispatch(ipc.Request{Command: ipc.CmdStart, Args: []string{"trust=0", ipc.EncodeSecret(testPass)}})
	if resp.Code != ipc.CodeOK {
		t.Fatalf("start = %d %s", resp.Code, resp.Message)
	}
	// 幂等：再看门狗式地敲一次 start 不该报错。
	resp = s.dispatch(ipc.Request{Command: ipc.CmdStart, Args: []string{"trust=0"}})
	if resp.Code != ipc.CodeOK || !strings.Contains(resp.Message, "已在运行") {
		t.Errorf("重复 start = %d %q", resp.Code, resp.Message)
	}
	// 已经在跑时带 --trust：顺带确保授信，同样报成功。
	resp = s.dispatch(ipc.Request{Command: ipc.CmdStart, Args: []string{"trust=1"}})
	if resp.Code != ipc.CodeOK {
		t.Errorf("带 --trust 的重复 start = %d %q", resp.Code, resp.Message)
	}
	if got := srv.Trusted(); len(got) != 1 {
		t.Errorf("带 --trust 的重复 start 应完成绑定，服务端授信终端 = %v", got)
	}

	if resp = s.dispatch(ipc.Request{Command: ipc.CmdStatus, Args: []string{"check"}}); resp.Code != ipc.CodeOK {
		t.Errorf("status check = %d %s", resp.Code, resp.Message)
	}
	if resp = s.dispatch(ipc.Request{Command: ipc.CmdStatus}); resp.Code != ipc.CodeOK || !strings.Contains(resp.Message, testVIP) {
		t.Errorf("status = %d %q，期望带上校园网地址", resp.Code, resp.Message)
	}

	if resp = s.dispatch(ipc.Request{Command: ipc.CmdUntrust, Args: []string{"all=1"}}); resp.Code != ipc.CodeOK {
		t.Errorf("untrust all = %d %s", resp.Code, resp.Message)
	}
	if got := srv.Trusted(); len(got) != 0 {
		t.Errorf("解除全部之后仍有授信终端: %v", got)
	}

	if resp = s.dispatch(ipc.Request{Command: ipc.CmdStop}); resp.Code != ipc.CodeOK {
		t.Errorf("stop = %d %s", resp.Code, resp.Message)
	}
	if resp = s.dispatch(ipc.Request{Command: ipc.CmdStop}); resp.Code != ipc.CodeOK || !strings.Contains(resp.Message, "本来就没有运行") {
		t.Errorf("重复 stop = %d %q，期望按成功处理", resp.Code, resp.Message)
	}
	if resp = s.dispatch(ipc.Request{Command: ipc.CmdStatus, Args: []string{"check"}}); resp.Code != ipc.CodeRejected {
		t.Errorf("链路不在 up 时 status check = %d，期望 409", resp.Code)
	}

	if resp = s.dispatch(ipc.Request{Command: ipc.CmdShutdown}); resp.Code != ipc.CodeOK {
		t.Errorf("shutdown = %d %s", resp.Code, resp.Message)
	}
	select {
	case <-s.Done():
	default:
		t.Error("shutdown 之后服务端应进入退出流程")
	}
}

func TestServerMapsAuthRequiredToPrompt(t *testing.T) {
	srv := newFakeServer(t, ztnatest.Options{RequireSMS: true, VerifyCode: testCode})
	svc := newTestService(t, srv, newTestConfig(t, srv))
	s := &Server{svc: svc, closing: make(chan struct{}), quit: make(chan struct{})}

	resp := s.dispatch(ipc.Request{Command: ipc.CmdStart, Args: []string{"trust=0", ipc.EncodeSecret(testPass)}})
	if resp.Code != ipc.CodeAuthRequired {
		t.Fatalf("start = %d %s，期望 428", resp.Code, resp.Message)
	}
	if !strings.Contains(resp.Message, "138****0000") {
		t.Errorf("428 的文案应带上验证码发到哪了，得到 %q", resp.Message)
	}
	if resp = s.dispatch(ipc.Request{Command: ipc.CmdAuth, Args: []string{testCode}}); resp.Code != ipc.CodeOK {
		t.Errorf("提交验证码 = %d %s", resp.Code, resp.Message)
	}
}

var _ = ztna.AsRejected
