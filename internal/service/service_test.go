package service

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
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
		// 假服务端用自签证书：控制面的系统信任链校验在这里必然失败，
		// 这条通道的校验由 internal/ztna 的用例单独覆盖。
		TLS: config.TLS{InsecureSkipVerify: true},
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

// TestMissingCredentialIsBadRequest 验证"缺凭据"按 400 报，而不是 500。
//
// 按状态码分流的脚本把 4xx 当输入问题、5xx 当服务故障：用户忘了填 username、
// 或既没写口令也没在请求里带口令时回 500，会把人引去查进程日志与服务端状态。
func TestMissingCredentialIsBadRequest(t *testing.T) {
	srv := newFakeServer(t, ztnatest.Options{})
	cases := []struct {
		name   string
		mutate func(*config.Config)
	}{
		{"配置里没有 username", func(c *config.Config) { c.Username = "" }},
		{"配置里没有口令", func(c *config.Config) { c.Password = "" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := newTestConfig(t, srv)
			c.mutate(cfg)
			svc := newTestService(t, srv, cfg)
			s := &Server{svc: svc, closing: make(chan struct{}), quit: make(chan struct{})}
			resp := s.dispatch(ipc.Request{Command: ipc.CmdStart})
			if resp.Code != ipc.CodeBadRequest {
				t.Errorf("状态码 = %d（%s），期望 400", resp.Code, resp.Message)
			}
		})
	}
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

// TestConnectFailureStillLogsOut 验证承载层挂载失败时，已经登录成功的会话也会
// 被登出。放不掉的话，控制面的“同一账号一个客户端”名额被一条没人持有的会话
// 占住，用户下一次 start 会被拒（映射成 409），直到服务端自己超时。
func TestConnectFailureStillLogsOut(t *testing.T) {
	srv := newFakeServer(t, ztnatest.Options{})
	svc := newTestService(t, srv, newTestConfig(t, srv))

	client, err := svc.clientFor()
	if err != nil {
		t.Fatalf("构造协议客户端: %v", err)
	}
	sess, err := client.Connect(context.Background(), ztna.ConnectOptions{Password: testPass})
	if err != nil {
		t.Fatalf("登录应当成功: %v", err)
	}

	// 让承载层挂载失败：对端地址没了，地址映射建不起来。这是真实的失败
	// 路径之一（配置写坏、设备被关掉），不必打桩。
	svc.br.peerAddr = nil

	if err := svc.finishConnect(sess); err == nil {
		t.Fatal("承载层挂载失败时 finishConnect 应当报错")
	}
	if got := srv.LogoutCount(); got != 1 {
		t.Errorf("登出 %d 次，期望 1 次（会话必须放掉，否则服务端名额被占）", got)
	}
	if st := svc.Status(); st.State != StateError {
		t.Errorf("状态 = %s，期望 error", st.State)
	}
}

// TestAttachInstallsPeerEveryTime 验证挂载是无条件的。
//
// 设备上现在是哪一对 peer 不留本地镜像：生产路径上 attach 之前必有 detach
// （它先摘 peer 再摘会话），所以"公钥没变就跳过"这条早退在生产里永远不成立。
// 判据是设备上的重装计数：每次挂载都该让它增长。
func TestAttachInstallsPeerEveryTime(t *testing.T) {
	srv := newFakeServer(t, ztnatest.Options{})
	cfg := newTestConfig(t, srv)
	// 配了 peer 公钥才会走到“装 peer”这一步。
	peer, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg.WireGuard.PeerPublicKey = peer.String()
	svc := newTestService(t, srv, cfg)

	client, err := svc.clientFor()
	if err != nil {
		t.Fatalf("构造协议客户端: %v", err)
	}
	sess, err := client.Connect(context.Background(), ztna.ConnectOptions{Password: testPass})
	if err != nil {
		t.Fatalf("登录应当成功: %v", err)
	}
	defer func() { _ = sess.Close(context.Background()) }()

	if err := svc.br.attach(sess); err != nil {
		t.Fatalf("第一次挂载: %v", err)
	}
	if got := svc.br.dev.PeerInstalls(); got != 1 {
		t.Fatalf("第一次挂载应当装一次 peer，累计 %d 次", got)
	}

	// 同一会话再挂一次：没有镜像可对，仍然是一次真实下发。
	if err := svc.br.attach(sess); err != nil {
		t.Fatalf("重复挂载: %v", err)
	}
	if got := svc.br.dev.PeerInstalls(); got != 2 {
		t.Fatalf("重复挂载应当再装一次 peer，累计 %d 次", got)
	}

	// 真的换了公钥仍然要重装，否则客户端接不进来。
	other, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	svc.br.peerKey = other
	if err := svc.br.attach(sess); err != nil {
		t.Fatalf("换公钥后挂载: %v", err)
	}
	if got := svc.br.dev.PeerInstalls(); got != 3 {
		t.Fatalf("换了公钥应当重装 peer，累计 %d 次", got)
	}
}

// TestLateTunnelReportIgnoredAfterTeardown 验证隧道那一代结束之后，它再投进来
// 的汇报不再被受理。
//
// 场景：重连连续失败、状态收敛成 error，而那条协程最后一次投出的"正在重连"
// 汇报才轮到自己被处理——用户于是看到一个 error 状态配一句"正在重连（第 N
// 次）"，可根本没有东西在重连，按状态分流的巡检脚本也会被误导。
func TestLateTunnelReportIgnoredAfterTeardown(t *testing.T) {
	srv := newFakeServer(t, ztnatest.Options{})
	svc := newTestService(t, srv, newTestConfig(t, srv))

	if err := svc.Start(false, testPass); err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	waitState(t, svc, StateUp)
	gen := svc.gen

	// 让这一代彻底结束：服务端没了，重连必然失败。
	srv.Close()
	srv.CloseTunnel()
	waitState(t, svc, StateError)
	if svc.Status().Retrying {
		t.Fatalf("收敛成 error 之后不该标着正在重连: %+v", svc.Status())
	}

	// 同一代的迟到汇报：必须被丢掉。
	reply := make(chan error, 1)
	svc.cmds <- &command{kind: cmdTunnelRetry, gen: gen, attempt: 9, err: errors.New("迟到的汇报"), reply: reply}
	select {
	case <-reply:
	case <-time.After(5 * time.Second):
		t.Fatal("注入的汇报没有被处理")
	}
	if svc.Status().Retrying {
		t.Errorf("过期代次的汇报仍被受理: %+v", svc.Status())
	}
	if strings.Contains(svc.Status().Detail, "正在重连") {
		t.Errorf("过期代次的汇报改掉了状态说明: %q", svc.Status().Detail)
	}
}

// TestHandleBadRequestGets400 回归：超长与畸形请求要回一条 400 再断开。
//
// 以前无论什么错误都直接 return：调用方读到 0 字节 + EOF，与"服务进程已经
// 退出"或"命令打到了别的实例"完全同形，也拿不到可重试的信号。
func TestHandleBadRequestGets400(t *testing.T) {
	srv := newFakeServer(t, ztnatest.Options{})
	svc := newTestService(t, srv, newTestConfig(t, srv))
	s := &Server{svc: svc, closing: make(chan struct{}), quit: make(chan struct{})}

	cases := []struct {
		name string
		send string
	}{
		{"超长行", strings.Repeat("x", ipc.MaxLineBytes+8192)},
		{"空请求", "\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			go s.handle(server)

			// net.Pipe 是同步的：写要放到另一条协程里，主协程才能读到响应。
			go func() { _, _ = io.WriteString(client, c.send) }()
			_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
			line, err := bufio.NewReader(client).ReadString('\n')
			if err != nil {
				t.Fatalf("没有读到响应（应当回 400）: %v", err)
			}
			resp, err := ipc.ParseResponse(line)
			if err != nil {
				t.Fatalf("响应无法解析: %v（%q）", err, line)
			}
			if resp.Code != ipc.CodeBadRequest {
				t.Fatalf("状态码 = %d（%q），期望 400", resp.Code, line)
			}
		})
	}
}

// TestStatusAddressFollowsServerUpdate 回归：服务端在会话中途换地址后，
// status 里的校园网地址必须跟着变。
//
// 数据面一直是现取的（承载映射按端点上的当前值改写），而 status 曾经是
// 一份写一次的快照：换地址后隧道照常工作，`njuvpn status` 却一直报旧地址，
// 按它排障或写脚本核对地址的人会被带偏。
func TestStatusAddressFollowsServerUpdate(t *testing.T) {
	srv := newFakeServer(t, ztnatest.Options{})
	svc := newTestService(t, srv, newTestConfig(t, srv))

	if err := svc.Start(false, testPass); err != nil {
		t.Fatalf("建立隧道失败: %v", err)
	}
	if st := svc.Status(); st.ClientIP != testVIP || st.PeerIP != "10.66.66.2" {
		t.Fatalf("地址 = %s / %s，期望 %s / 10.66.66.2", st.ClientIP, st.PeerIP, testVIP)
	}

	const newer = "172.16.0.10"
	if err := srv.SendVIPUpdate(newer); err != nil {
		t.Fatalf("下发地址变更: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for svc.Status().ClientIP != newer {
		if time.Now().After(deadline) {
			t.Fatalf("地址变更后 status 仍是 %q，期望 %q", svc.Status().ClientIP, newer)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// 会话摘掉之后两个地址都不再显示（不是靠状态迁移时逐处清）。
	if err := svc.Stop(); err != nil {
		t.Fatalf("断开失败: %v", err)
	}
	if st := svc.Status(); st.ClientIP != "" || st.PeerIP != "" {
		t.Fatalf("断开后仍显示地址: %q / %q", st.ClientIP, st.PeerIP)
	}
}

// TestListenHostTablesAgree 钉住 config 与 wireguard 的两份取值集合一致。
//
// config 是叶子包，为了不让依赖图绕圈自己留了一份写法集合（见
// config.validateListenHost 的注释），一致性原来只靠注释提醒：从一边删掉
// "any"，另一边照样放行，用户以为在监听全部网卡，承载层却静默回落到回环。
func TestListenHostTablesAgree(t *testing.T) {
	for _, v := range []string{"", "loopback", "local", "127.0.0.1", "all", "any", "0.0.0.0", "loop", "0.0.0.1", "ALL"} {
		_, wgErr := wireguard.ParseListenHost(v)
		cfgErr := loadWithListenHost(t, v)
		if (wgErr == nil) != (cfgErr == nil) {
			t.Errorf("取值 %q：wireguard 说 (err=%v)，config 说 (err=%v)——两份表必须一致", v, wgErr, cfgErr)
		}
	}
}

// loadWithListenHost 用最小可加载的配置跑一遍 config.Load，只为看校验结果。
func loadWithListenHost(t *testing.T, value string) error {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	content := "server: vpn.example\nusername: u\nmtu: 1320\nwireguard:\n  peer_address: 10.66.66.2\n  listen_host: \"" + value + "\"\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := config.Load(path)
	return err
}
