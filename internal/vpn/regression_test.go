package vpn

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/vpntest"
)

// 一次完整登录的脚本：登录页、口令页、portal、query-ip、两条流。
//
// 参数说明：loginResponse 是 /por/login_psw.csp 的响应，
// 用来构造"直接成功""要求短信""要求 TOTP"等不同剧本。
type script struct {
	portal        *vpntest.Portal
	tunnel        *vpntest.Tunnel
	loginResponse string
}

func newScript(t *testing.T) *script {
	t.Helper()
	s := &script{
		portal: vpntest.NewPortal(),
		tunnel: vpntest.NewTunnel(),
	}
	s.loginResponse = `<Auth><Result>1</Result><NextAuth>-1</NextAuth><TwfID>0123456789abcdef</TwfID></Auth>`
	s.portal.On("/por/login_auth.csp", vpntest.Response{Body: vpntest.LoginAuthPage()})
	// 第二条 TwfID 与第一条不同，用来验证会话标识确实被更新。
	s.portal.On("/por/login_psw.csp", vpntest.Response{
		Body: `<Auth><Result>1</Result><NextAuth>-1</NextAuth><TwfID>fedcba9876543210</TwfID></Auth>`,
	})
	s.portal.On("/por/logout.csp", vpntest.Response{
		Body: `<Auth><Message><![CDATA[logout user success]]></Message></Auth>`,
	})
	return s
}

// 回归：短信接口失败时，会话标识不能丢。
//
// 口令已经通过校验，服务端可能已经给这个会话留了名额；TwfID 交不出去就
// 登不掉，那个名额会一直占着（同一账号只允许一条会话）。
func TestSMSRequestFailureKeepsTwfID(t *testing.T) {
	s := newScript(t)
	s.portal.Set("/por/login_psw.csp", vpntest.Response{
		Body: `<Auth><Result>1</Result><NextAuth>2</NextAuth><NextService>auth/sms</NextService></Auth>`,
	})
	// 短信接口坏了：服务端 500。
	s.portal.Set("/por/login_sms.csp", vpntest.Response{Status: 500, Body: "boom"})
	client := newTestClient(t, s)

	sess, err := client.Connect(context.Background(), ConnectOptions{Username: "u", Password: "p"})
	if err == nil {
		t.Fatal("短信接口失败时应当报错")
	}
	if sess == nil || sess.TwfID() == "" {
		t.Fatal("失败路径也必须交出会话标识，否则这个会话永远登不掉")
	}
	if err := sess.Close(context.Background()); err != nil {
		t.Fatalf("登出失败: %v", err)
	}
	if s.portal.Count("/por/logout.csp") == 0 {
		t.Fatal("没有向服务端发出登出请求")
	}
}

// newBareConn 返回一条"握手不完整"的连接：它不实现 ServerHelloSessionID。
func newBareConn() net.Conn {
	client, server := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, server) }()
	return client
}

func newTestClient(t *testing.T, s *script) *Client {
	t.Helper()
	return New(Options{
		Server:    "vpn.example.edu:443",
		PortalTLS: s.tunnel.Dial,
		TunnelTLS: s.tunnel.Dial,
		HTTP:      s.portal.HTTPClient(),
		Timeouts:  Timeouts{HTTP: 5 * time.Second, Handshake: 5 * time.Second},
	})
}

// 回归：服务端返回的页面里缺少 <TwfID> / <RSA_ENCRYPT_KEY> 时，
// 旧实现直接对 FindSubmatch 的结果取下标，一次越界就把服务进程带走。
func TestWebLoginMalformedPagesReturnErrors(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"空响应", ""},
		{"HTML 错误页", "<html><body>502 Bad Gateway</body></html>"},
		{"只有 TwfID", "<Auth><TwfID>0123456789abcdef</TwfID></Auth>"},
		{"只有公钥", "<Auth><RSA_ENCRYPT_KEY>010001</RSA_ENCRYPT_KEY></Auth>"},
		{"TwfID 为空", "<Auth><TwfID></TwfID><RSA_ENCRYPT_KEY>010001</RSA_ENCRYPT_KEY></Auth>"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newScript(t)
			s.portal.Set("/por/login_auth.csp", vpntest.Response{Body: c.body})
			client := newTestClient(t, s)

			_, err := client.Connect(context.Background(), ConnectOptions{Username: "u", Password: "p"})
			if err == nil {
				t.Fatal("畸形响应必须返回错误")
			}
			var protoErr *ProtocolError
			if !errors.As(err, &protoErr) {
				t.Errorf("期望 ProtocolError，实际 %T: %v", err, err)
			}
		})
	}
}

// 回归：TLS 握手没走完时 HandshakeState.ServerHello 是 nil，
// 旧实现直接解引用它取 SessionId。
func TestPortalTokenHandlesMissingHandshakeState(t *testing.T) {
	s := newScript(t)
	client := New(Options{
		Server: "vpn.example.edu:443",
		// 模拟一条"连上了但拿不到 ServerHello"的 TLS 连接。
		PortalTLS: func(ctx context.Context) (net.Conn, error) { return newBareConn(), nil },
		TunnelTLS: s.tunnel.Dial,
		HTTP:      s.portal.HTTPClient(),
		Timeouts:  Timeouts{HTTP: 5 * time.Second, Handshake: 5 * time.Second},
	})

	if _, err := client.portalToken(context.Background(), "0123456789abcdef"); err == nil {
		t.Fatal("拿不到 ServerHello 必须返回错误")
	}
}

// 回归：ServerHello 的 SessionId 短于 16 字节时，
// 旧实现 hex 编码后取前 31 个字符，直接越界 panic。
func TestPortalTokenRejectsShortSessionID(t *testing.T) {
	for _, idLen := range []int{0, 1, 8, 15} {
		s := newScript(t)
		s.tunnel.SetSessionID(make([]byte, idLen))
		client := newTestClient(t, s)

		_, err := client.portalToken(context.Background(), "0123456789abcdef")
		if err == nil {
			t.Fatalf("SessionId 长度 %d 时必须返回错误", idLen)
		}
		var protoErr *ProtocolError
		if !errors.As(err, &protoErr) {
			t.Errorf("期望 ProtocolError，实际 %v", err)
		}
	}
}

// 回归：token + TwfID 组装 48 字节时，旧实现用 (*[48]byte)([]byte(...))，
// 长度不足会 panic，长度超出会静默截断。
func TestStreamTokenLengthValidation(t *testing.T) {
	valid := strings.Repeat("a", tokenTotalLen)

	if _, err := streamToken("test", valid, "0123456789abcdef"); err != nil {
		t.Errorf("合法输入不应报错: %v", err)
	}
	if _, err := streamToken("test", valid[:tokenTotalLen-1], "0123456789abcdef"); err == nil {
		t.Error("token 过短必须报错")
	}
	if _, err := streamToken("test", valid+"x", "0123456789abcdef"); err == nil {
		t.Error("token 过长必须报错")
	}
	if _, err := streamToken("test", valid, "0123456789abcde"); err == nil {
		t.Error("TwfID 过短必须报错")
	}
	// 长于 16 字节按前 16 字节处理，与旧行为一致，不报错。
	if _, err := streamToken("test", valid, "0123456789abcdefEXTRA"); err != nil {
		t.Errorf("TwfID 偏长不应报错: %v", err)
	}
}

// 回归：会话标识是 16 字符，redact 保留尾部会泄漏其中两个字符。
// 回归：服务端回了预期之外的字节时必须终止重试。
//
// 这类错误不会自愈，而密集重试会把账号打进服务端的"被拒"状态，
// 每次重试都要等满退避（3 次 × 30 秒）才报错。
func TestRetryableTreatsProtocolErrorAsTerminal(t *testing.T) {
	proto := &ProtocolError{Step: "query-ip", Reason: "控制码 0x0f"}
	if retryable(proto) {
		t.Error("协议不符不该被当成可重试")
	}
	// 控制码仍然按自己的规则走：可重试的照样可重试。
	if !retryable(&ControlError{Code: ControlIPBusy}) {
		t.Error("IpBusy 应当可重试")
	}
	// ServerReset 不算可重试：实测它是"建得太密"或"上条会话没释放"，
	// 继续重试会把账号推得更远，正确做法是等几分钟。
	if retryable(&ControlError{Code: ControlServerReset}) {
		t.Error("ServerReset 不该被当成可重试")
	}
}

// 回归：标签内容可能跨行（服务端在 CDATA 里放多行文本），
// 只匹配单行会取不到值，报成"缺少该标签"。
func TestTagValueMatchesAcrossLines(t *testing.T) {
	body := []byte("<Auth>" + "\n" +
		"<Message><![CDATA[第一行" + "\n" + "第二行]]></Message>" + "\n" +
		"</Auth>")
	got, ok := tagValue(body, "Message")
	if !ok {
		t.Fatal("跨行的标签内容也要能取到")
	}
	if !strings.Contains(got, "第二行") {
		t.Errorf("内容不完整: %q", got)
	}
}

func TestRedactDoesNotLeakTail(t *testing.T) {
	secret := "0123456789abcdef"
	got := redact(secret)
	if strings.Contains(got, secret[len(secret)-2:]) {
		t.Errorf("脱敏结果泄漏了尾部字符: %q", got)
	}
	if strings.Contains(got, secret[len(secret)-4:]) {
		t.Errorf("脱敏结果泄漏了尾部片段: %q", got)
	}
}

// 回归（功能不可用）：复用 TwfID 继续登录时，提交的验证码必须真的发出去。
// 旧实现的 Probe 在 twfID 非空时直接跳过验证码分支，整个短信流程没有成功路径。
func TestConnectSubmitsCodeWhenReusingSession(t *testing.T) {
	s := newScript(t)
	// 登录页已经通过，剩下两步：提交验证码 + 后续流程。
	s.portal.On("/por/login_sms1.csp", vpntest.Response{
		Body: `<Auth>Auth sms suc</Auth><TwfID>aabbccddeeff0011</TwfID>`,
	})
	client := newTestClient(t, s)

	sess, err := client.Connect(context.Background(), ConnectOptions{
		Username: "u",
		Password: "p",
		TwfID:    "0123456789abcdef",
		Code:     "123456",
		AuthKind: ErrAuthSMS,
	})
	if err != nil {
		t.Fatalf("带验证码的连接不应失败: %v", err)
	}
	defer sess.Close(context.Background())

	form := s.portal.LastForm("/por/login_sms1.csp")
	if form == nil {
		t.Fatal("验证码没有被提交到服务端")
	}
	if got := form.Get("svpn_inputsms"); got != "123456" {
		t.Errorf("提交的验证码 = %q，期望 %q", got, "123456")
	}
	if sess.TwfID() != "aabbccddeeff0011" {
		t.Errorf("会话标识没有更新为新值: %q", sess.TwfID())
	}
	if sess.ClientIP() == "" {
		t.Error("没有拿到分配地址")
	}
}

// 登录页要求短信验证码且调用方没给验证码时，必须返回带会话标识的
// AuthRequiredError，而不是丢掉 code 继续往下走。
func TestConnectReportsAuthRequiredWithTwfID(t *testing.T) {
	s := newScript(t)
	s.portal.Set("/por/login_psw.csp", vpntest.Response{
		Body: `<Auth><Result>1</Result><NextAuth>2</NextAuth><NextService>auth/sms</NextService></Auth>`,
	})
	s.portal.On("/por/login_sms.csp", vpntest.Response{
		Body: `<Auth><ErrorCode>1</ErrorCode><USER_PHONE>****</USER_PHONE><SmsSendInterval>178</SmsSendInterval></Auth>`,
	})
	client := newTestClient(t, s)

	sess, err := client.Connect(context.Background(), ConnectOptions{Username: "u", Password: "p"})
	if err == nil {
		t.Fatal("需要二次验证时必须返回错误")
	}
	authErr, ok := AsAuthRequired(err)
	if !ok {
		t.Fatalf("期望 AuthRequiredError，实际 %T: %v", err, err)
	}
	if authErr.TwfID != "0123456789abcdef" {
		t.Errorf("AuthRequiredError 丢了会话标识: %q", authErr.TwfID)
	}
	if !errors.Is(err, ErrAuthSMS) {
		t.Errorf("应能识别为短信验证，实际 %v", err)
	}
	// 会话对象仍要带着 TwfID 返回，调用方才能登出。
	if sess == nil || sess.TwfID() == "" {
		t.Fatal("部分成功时必须返回可登出的会话")
	}
	sess.Close(context.Background())
}

// 验证码错误要能区分出来（会话仍有效），不能当成致命错误。
func TestConnectWrongCodeKeepsSession(t *testing.T) {
	s := newScript(t)
	s.portal.On("/por/login_sms1.csp", vpntest.Response{
		Body: `<Auth>Auth sms failed. invalid code</Auth>`,
	})
	client := newTestClient(t, s)

	sess, err := client.Connect(context.Background(), ConnectOptions{
		Username: "u", Password: "p",
		TwfID: "0123456789abcdef", Code: "000000", AuthKind: ErrAuthSMS,
	})
	if err == nil {
		t.Fatal("验证码错误必须返回错误")
	}
	if !IsAuthCodeError(err) {
		t.Errorf("验证码错误应被识别为可重试的输入错误，实际 %v", err)
	}
	if sess == nil || sess.TwfID() != "0123456789abcdef" {
		t.Error("会话标识应保持不变，用户可以再输一次")
	}
	sess.Close(context.Background())
}

// 部分失败（登录成功、建隧道失败）时，返回的会话必须能登出。
func TestConnectPartialFailureAllowsLogout(t *testing.T) {
	s := newScript(t)
	s.tunnel.RejectQueryIP(ControlShutdown) // 终止性拒绝，不会重试
	client := newTestClient(t, s)

	sess, err := client.Connect(context.Background(), ConnectOptions{Username: "u", Password: "p"})
	if err == nil {
		t.Fatal("query-ip 被拒时必须返回错误")
	}
	var ctrl *ControlError
	if !errors.As(err, &ctrl) || ctrl.Code != ControlShutdown {
		t.Fatalf("期望 Shutdown 控制错误，实际 %v", err)
	}
	if sess == nil {
		t.Fatal("失败路径也必须返回会话，否则无法登出")
	}
	if err := sess.Close(context.Background()); err != nil {
		t.Fatalf("登出失败: %v", err)
	}
	if n := s.portal.Count("/por/logout.csp"); n != 1 {
		t.Errorf("登出请求次数 = %d，期望 1", n)
	}
}

// 登出必须只发一次：进程退出路径会多次调用 Close。
func TestSessionCloseIsIdempotent(t *testing.T) {
	s := newScript(t)
	client := newTestClient(t, s)

	sess, err := client.Connect(context.Background(), ConnectOptions{Username: "u", Password: "p"})
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sess.Close(context.Background())
		}()
	}
	wg.Wait()

	if n := s.portal.Count("/por/logout.csp"); n != 1 {
		t.Errorf("并发 Close 发出了 %d 次登出，期望 1", n)
	}
}

// ctx 取消后登出也必须发出去：退出路径上的上下文往往已经被取消。
func TestLogoutRunsWithCanceledContext(t *testing.T) {
	s := newScript(t)
	client := newTestClient(t, s)

	sess, err := client.Connect(context.Background(), ConnectOptions{Username: "u", Password: "p"})
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sess.Close(ctx); err != nil {
		t.Fatalf("登出失败: %v", err)
	}
	if n := s.portal.Count("/por/logout.csp"); n != 1 {
		t.Errorf("取消的上下文下没有发出登出请求（%d 次）", n)
	}
}

// 回归：query-ip 的回执可能分两段到达。
//
// 隧道是字节流，"服务端写了 36 字节"不等于"我们一次 Read 就能拿到"。
// 旧实现只读一次，拿到 4 字节就判成响应过短——那是不可重试的协议错误，
// 三次退避一次都没走，整次 start 直接失败（真机出现过：日志里
// "query ip: read 4 bytes" 之后就是 unexpected query ip reply）。
func TestQueryIPAcceptsReplySplitAcrossReads(t *testing.T) {
	local, remote := net.Pipe()
	t.Cleanup(func() { remote.Close() })

	go func() {
		// 先读掉请求，再分两段写回执。
		buf := make([]byte, 4096)
		if _, err := remote.Read(buf); err != nil {
			return
		}
		if _, err := remote.Write([]byte{ControlSendIP, 0, 0, 0}); err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
		_, _ = remote.Write([]byte{172, 29, 56, 18})
	}()

	client := New(Options{
		TunnelTLS: func(context.Context) (net.Conn, error) { return local, nil },
	})
	var token [streamTokenLen]byte
	ip, conn, err := client.queryIP(context.Background(), token, false)
	if err != nil {
		t.Fatalf("分段到达的回执应当被接受，实际 %v", err)
	}
	defer conn.Close()
	if got := ip.String(); got != "172.29.56.18" {
		t.Fatalf("分配的地址 = %s，想要 172.29.56.18", got)
	}
}

// 回归：退避等待期间断开（stop / 退出）必须立刻生效。
//
// 旧实现里 Run 退出时把会话上的 cancel 清成 nil，退避中的循环因此叫不醒：
// 会话明明已经断开，循环还在睡，睡醒之后又在已关闭的会话上重建两条流。
func TestRetryBackoffIsInterruptedByCloseLocal(t *testing.T) {
	s := newScript(t)
	// 两条流都被一个可重试的控制码拒绝：Run 立刻失败，进入退避等待。
	s.tunnel.RejectStream(0x05, ControlIPBusy)
	sess := connectedSession(t, s)

	done := make(chan error, 1)
	go func() {
		done <- sess.RunWithRetryNotify(context.Background(), RetryPolicy{
			Attempts: 5, Base: 10 * time.Second, Max: 30 * time.Second,
		}, nil)
	}()

	// 等它真的进入退避：第一次 Run 已经失败并睡下。
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	sess.CloseLocal()

	select {
	case <-done:
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("CloseLocal 之后退避还要睡 %s 才醒", elapsed)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("CloseLocal 没有唤醒退避中的重连循环")
	}
}
