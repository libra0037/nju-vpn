package ztna

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/ztnatest"
)

// 这些用例跑的是完整的协议流程：假服务端在本地扮演控制面与隧道节点，
// 一个真实服务端都不碰。上线前的实测仍然要做，但"改一行就悄悄跑不通"这种
// 事由它们挡住。

const (
	testUser = "600000000000"
	testPass = "secret"
	testCode = "123456"
)

func newFake(t *testing.T, opts ztnatest.Options) *ztnatest.Server {
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

func newTestClient(t *testing.T, srv *ztnatest.Server, password string) *Client {
	t.Helper()
	client, err := New(Options{
		NodeSPKIPins:     [][32]byte{srv.SPKIPin()},
		ReconnectBackoff: time.Millisecond,
		Server:           "vpn.test",
		DialAddr:         srv.Addr(),
		Dial:             srv.Dial,
		Username:         testUser,
		Password:         password,
		DeviceID:         "device-test-1",
		Logf:             t.Logf,
		// 假服务端用自签证书，控制面的系统信任链校验在这里必然失败——
		// 这条通道的校验由 internal/ztna/verify_test.go 单独覆盖。
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestConnectWithSMSTrustAndData(t *testing.T) {
	srv := newFake(t, ztnatest.Options{RequireSMS: true, VerifyCode: testCode})
	client := newTestClient(t, srv, testPass)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	sess, err := client.Connect(ctx, ConnectOptions{})
	authErr, ok := AsAuthRequired(err)
	if !ok {
		t.Fatalf("应停在等验证码这一步，得到 %v", err)
	}
	if !strings.Contains(authErr.Hint, "***0000") {
		t.Errorf("提示里应带上脱敏手机号，得到 %q", authErr.Hint)
	}
	// 半完成的会话必须原样留着：提前登出会把它作废，验证码就再也提交不上
	// （假服务端按"登出即作废"建模，这里发出过登出就会在下面提交验证码时
	// 拿到 75500002）。
	if n := srv.LogoutCount(); n != 0 {
		t.Fatalf("拿到验证码提示之前不该登出，已登出 %d 次", n)
	}

	hint, err := sess.SMSPrompt(ctx)
	if err != nil {
		t.Fatalf("发送验证码失败: %v", err)
	}
	if hint == "" {
		t.Error("发送验证码应给出提示文案")
	}
	if srv.SMSSends() != 1 {
		t.Errorf("服务端收到 %d 次发码请求，期望 1", srv.SMSSends())
	}

	// 验证码错误：会话还活着，可以再输一次。
	if err := sess.Auth(ctx, "000000"); err == nil {
		t.Fatal("错误的验证码应被拒绝")
	} else if _, ok := AsRejected(err); !ok {
		t.Errorf("应报成被拒绝，得到 %v", err)
	}

	if err := sess.Auth(ctx, testCode); err != nil {
		t.Fatalf("正确的验证码应通过: %v", err)
	}
	if got := sess.ClientIP().String(); got != "172.16.0.9" {
		t.Errorf("分配的地址 = %s，期望 172.16.0.9", got)
	}
	if srv.Tunnels() != 1 {
		t.Errorf("隧道连接数 = %d，期望 1", srv.Tunnels())
	}

	// --trust 的续跑路径：绑定本机。
	if err := sess.EnsureTrusted(ctx); err != nil {
		t.Fatalf("绑定授信终端失败: %v", err)
	}
	if got := srv.Trusted(); len(got) != 1 || got[0] != "self-1" {
		t.Errorf("服务端的授信终端 = %v，期望 [self-1]", got)
	}

	// 上行：承载层丢进来的包要经过逐流鉴权再发出去。
	pkt := ipv4TCP("172.16.0.9", "10.1.2.3", 40000, 443, []byte("hello"))
	if err := sess.Endpoint().Send(pkt); err != nil {
		t.Fatalf("上行失败: %v", err)
	}
	waitFor(t, "服务端收到上行包", func() bool { return len(srv.Uplink()) == 1 })
	if srv.AuthRequests() == 0 {
		t.Error("上行前应先发逐流鉴权请求")
	}

	// 下行：隧道收到的包要交给承载层的回调。
	down := make(chan []byte, 4)
	sess.Endpoint().SetDownlink(func(b []byte) { down <- b })
	if err := srv.SendDownlink(ipv4TCP("10.1.2.3", "172.16.0.9", 443, 40000, []byte("world"))); err != nil {
		t.Fatalf("下发失败: %v", err)
	}
	select {
	case got := <-down:
		if len(got) == 0 {
			t.Error("下行包为空")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("没有收到下行包")
	}

	if err := sess.Close(ctx); err != nil {
		t.Fatalf("关闭会话失败: %v", err)
	}
	if err := sess.Close(ctx); err != nil {
		t.Errorf("重复关闭应无害: %v", err)
	}
	if n := srv.LogoutCount(); n != 1 {
		t.Errorf("登出次数 = %d，期望 1", n)
	}
}

// TestConnectLegacySMSForm 回归：旧形态的短信提交用表单体，Content-Type 必须
// 跟着改。
//
// 服务端不给 authId 时它要的是表单（application/x-www-form-urlencoded），而
// do() 默认给带体的请求设 JSON 类型：按 Content-Type 分派的网关会直接拒收。
// 假服务端现在严格按 Content-Type 解析，写错就提交不上。
func TestConnectLegacySMSForm(t *testing.T) {
	srv := newFake(t, ztnatest.Options{RequireSMS: true, VerifyCode: testCode, LegacySMSForm: true})
	client := newTestClient(t, srv, testPass)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	sess, err := client.Connect(ctx, ConnectOptions{})
	if _, ok := AsAuthRequired(err); !ok {
		t.Fatalf("旧形态也应停在等验证码这一步，得到 %v", err)
	}
	if _, err := sess.SMSPrompt(ctx); err != nil {
		t.Fatalf("发送验证码失败: %v", err)
	}
	if err := sess.Auth(ctx, testCode); err != nil {
		t.Fatalf("表单提交验证码失败: %v", err)
	}
	if got := sess.ClientIP().String(); got != "172.16.0.9" {
		t.Errorf("分配的地址 = %s，期望 172.16.0.9", got)
	}
}

func TestConnectWithoutSecondFactor(t *testing.T) {
	srv := newFake(t, ztnatest.Options{})
	client := newTestClient(t, srv, testPass)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	sess, err := client.Connect(ctx, ConnectOptions{})
	if err != nil {
		t.Fatalf("不需要二次验证时 Connect 应直接成功: %v", err)
	}
	defer sess.Close(ctx)
	if sess.username != testUser {
		t.Errorf("账号 = %q，期望 %q", sess.username, testUser)
	}
	if srv.SMSSends() != 0 {
		t.Errorf("不该发短信，收到 %d 次请求", srv.SMSSends())
	}
}

func TestConnectUsesPasswordFromOptions(t *testing.T) {
	srv := newFake(t, ztnatest.Options{})
	client := newTestClient(t, srv, "")

	ctx := context.Background()
	if _, err := client.Connect(ctx, ConnectOptions{}); err == nil {
		t.Fatal("没有口令时应失败")
	}

	sess, err := client.Connect(ctx, ConnectOptions{Password: testPass})
	if err != nil {
		t.Fatalf("带口令的 Connect 应成功: %v", err)
	}
	defer sess.Close(ctx)

	if _, err := client.Connect(ctx, ConnectOptions{Password: "wrong"}); err == nil {
		t.Fatal("错误口令应被拒绝")
	} else {
		// 实测：口令错误回的是 75500000。它不能被当成"会话已失效"——
		// 那样用户看到的是 500 会话失效，而不是"口令不对"。
		if _, ok := AsRejected(err); !ok {
			t.Errorf("错误口令应报成被拒绝，得到 %v", err)
		}
		var gone *ErrSessionGone
		if errors.As(err, &gone) {
			t.Errorf("口令错误不该被当成会话失效: %v", err)
		}
	}
}

// TestDeviceSessionWithoutLoginDoesNotPanic 验证登录在早期就失败时，交出去的
// 空会话不会让后续方法空指针 panic。
//
// OpenDevices 故意在失败时也返回一个对象：登录走到一半失败时那个会话占着
// 服务端名额，调用方要拿它去登出。空会话因此是合法状态，方法必须自己挡住。
func TestDeviceSessionWithoutLoginDoesNotPanic(t *testing.T) {
	// 离线拨号失败发生在会话构造之后，仍须能关闭返回的半完成对象。
	client, err := New(Options{Server: "vpn.test", DialAddr: "vpn.test:443", DeviceID: "test", Dial: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("offline") }, Username: testUser, Password: testPass, NodeSPKIPins: [][32]byte{{1}}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	d, err := client.OpenDevices(ctx, "")
	if err == nil {
		t.Fatal("离线拨号应当报错")
	}
	if d == nil {
		t.Fatal("失败时也该返回可安全使用的对象（调用方要能关掉它）")
	}
	if _, err := d.Status(ctx); err == nil {
		t.Error("没有会话时查询状态应当报错")
	}
	if _, err := d.Trust(ctx); err == nil {
		t.Error("没有会话时绑定应当报错")
	}
	if _, err := d.Untrust(ctx, true); err == nil {
		t.Error("没有会话时解绑应当报错")
	}
	if err := d.Auth(ctx, "123456"); err == nil {
		t.Error("没有会话时提交验证码应当报错")
	}
	if err := d.Close(ctx); err != nil {
		t.Errorf("关掉空会话应当无害: %v", err)
	}
}

func TestOpenDevicesTrustAndUntrust(t *testing.T) {
	srv := newFake(t, ztnatest.Options{})
	client := newTestClient(t, srv, testPass)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	d, err := client.OpenDevices(ctx, "")
	if err != nil {
		t.Fatalf("打开授信终端会话失败: %v", err)
	}
	defer d.Close(ctx)

	st, err := d.Status(ctx)
	if err != nil {
		t.Fatalf("查询状态失败: %v", err)
	}
	if st.Trusted {
		t.Error("本机一开始不该是授信终端")
	}
	if st.SelfID != "self-1" || st.Max != 3 {
		t.Errorf("查询结果里的标识或上限不对: %+v", st)
	}

	if st, err = d.Trust(ctx); err != nil {
		t.Fatalf("绑定失败: %v", err)
	}
	if !st.Trusted || st.Count != 1 {
		t.Errorf("绑定后的状态不对: %+v", st)
	}

	// 只做授信终端操作时不该顺手建隧道。
	if srv.Tunnels() != 0 {
		t.Errorf("设备操作不该建立隧道，收到 %d 条", srv.Tunnels())
	}

	if st, err = d.Untrust(ctx, false); err != nil {
		t.Fatalf("解绑失败: %v", err)
	}
	if st.Trusted || len(srv.Trusted()) != 0 {
		t.Errorf("解绑后仍有授信终端: %+v", srv.Trusted())
	}
}

func TestOpenDevicesUntrustAll(t *testing.T) {
	srv := newFake(t, ztnatest.Options{Trusted: []string{"other-1", "other-2"}})
	client := newTestClient(t, srv, testPass)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	d, err := client.OpenDevices(ctx, "")
	if err != nil {
		t.Fatalf("打开授信终端会话失败: %v", err)
	}
	defer d.Close(ctx)

	if st, err := d.Untrust(ctx, true); err != nil {
		t.Fatalf("解除全部授信失败: %v", err)
	} else if st.Count != 0 {
		t.Errorf("解除全部之后仍有 %d 个授信终端", st.Count)
	}
	if got := srv.Trusted(); len(got) != 0 {
		t.Errorf("服务端仍有授信终端: %v", got)
	}
}

func TestConnectRejectsAlreadyOnline(t *testing.T) {
	srv := newFake(t, ztnatest.Options{})
	client := newTestClient(t, srv, testPass)
	ctx := context.Background()
	if _, err := client.Connect(ctx, ConnectOptions{}); err != nil {
		t.Fatalf("第一次登录应成功: %v", err)
	}
	if _, err := client.Connect(ctx, ConnectOptions{}); err != nil {
		t.Logf("第二次登录的错误（假服务端不限制在线数）: %v", err)
	}
}

// TestReconnectRotatesNodes 验证重连会换节点：当前节点连不上时，资源表里
// 的下一个候选节点把隧道接起来，不必重新登录（短信模式下重登要再花一条
// 验证码，还要抢服务端那条唯一的名额）。
func TestReconnectRotatesNodes(t *testing.T) {
	const (
		nodeA = "10.9.9.1:441"
		nodeB = "10.9.9.2:441"
	)
	srv := newFake(t, ztnatest.Options{Nodes: []string{nodeA, nodeB}})

	// 登录时只有 A 可达，选中的必然是 A；登录之后把 A 关掉、把 B 打开，
	// 模拟"A 重启/维护，别的节点还好着"。
	var mu sync.Mutex
	reachable := map[string]bool{nodeA: true}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == srv.Addr() {
			// 控制面走的是服务端自己的地址，不受节点开关影响。
			return srv.Dial(ctx, network, addr)
		}
		mu.Lock()
		up := reachable[addr]
		mu.Unlock()
		if !up {
			return nil, fmt.Errorf("节点 %s 不可达", addr)
		}
		return srv.Dial(ctx, network, srv.Addr())
	}
	setReachable := func(a, b bool) {
		mu.Lock()
		reachable = map[string]bool{nodeA: a, nodeB: b}
		mu.Unlock()
	}

	client := newTestClient(t, srv, testPass)
	client.opts.Dial = dial // newTestClient 用的是 srv.Dial，这里换成受控的
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sess, err := client.Connect(ctx, ConnectOptions{})
	if err != nil {
		t.Fatalf("登录应成功: %v", err)
	}
	defer sess.Close(context.Background())
	if sess.node != nodeA {
		t.Fatalf("登录选中的节点 = %s，期望 %s", sess.node, nodeA)
	}

	restored := make(chan struct{}, 1)
	done := make(chan error, 1)
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		done <- sess.Run(ctx, LinkEvents{Restored: func() { restored <- struct{}{} }})
	}()
	// 收尾要等到 Run 真的退出：它还会用 t.Logf 记日志（会话自己的日志函数
	// 就是它），用例返回之后再写就是与 testing 包的收尾状态打架。
	defer func() {
		cancel()
		select {
		case <-runDone:
		case <-time.After(5 * time.Second):
			t.Error("ctx 取消之后 Run 没有退出")
		}
	}()

	setReachable(false, true)
	srv.CloseTunnel()

	select {
	case <-restored:
	case err := <-done:
		t.Fatalf("重连应换到下一个节点，却以失败收场: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("重连没有换节点，等不到链路恢复")
	}
	if sess.node != nodeB {
		t.Errorf("重连之后的节点 = %s，期望 %s", sess.node, nodeB)
	}
	if n := srv.LogoutCount(); n != 0 {
		t.Errorf("重连不该登出，登出次数 = %d", n)
	}
	if n := srv.Tunnels(); n < 2 {
		t.Errorf("服务端上的隧道连接数 = %d，期望至少 2", n)
	}
}

// TestTunnelSurvivesHeartbeatRoundTrip 验证心跳真的走通了一次往返，而且之后
// 隧道仍然活着。
//
// 这条路径此前在离线环境里没有被覆盖过：假服务端读心跳帧时没消费那两个保留
// 字节，残留的 0x00 0x00 被当成下一轮的帧头（版本不是 0x05），它于是自己把
// 隧道断掉——凡是活过 15 秒的用例都会看到一次莫名其妙的断链。
//
// 心跳间隔 15 秒，跑一轮要 20 秒上下，-short 下跳过。
func TestTunnelSurvivesHeartbeatRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("需要等一个心跳周期（15 秒），-short 下跳过")
	}
	srv := newFake(t, ztnatest.Options{})
	client := newTestClient(t, srv, testPass)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	sess, err := client.Connect(ctx, ConnectOptions{})
	if err != nil {
		t.Fatalf("登录应成功: %v", err)
	}
	defer sess.Close(context.Background())

	down := make(chan error, 1)
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		down <- sess.Run(ctx, LinkEvents{})
	}()
	defer func() {
		cancel()
		select {
		case <-runDone:
		case <-time.After(5 * time.Second):
			t.Error("ctx 取消之后 Run 没有退出")
		}
	}()

	// 等第一次心跳：间隔 15 秒，给到 40 秒；期间隧道断开就直接失败。
	deadline := time.Now().Add(40 * time.Second)
	for srv.Heartbeats() < 1 {
		if time.Now().After(deadline) {
			t.Fatal("一个心跳周期（15 秒）内没有收到心跳")
		}
		select {
		case err := <-down:
			t.Fatalf("隧道在心跳之前断开: %v", err)
		case <-time.After(50 * time.Millisecond):
		}
	}
	// 心跳之后再看几秒：残留字节若没读掉，隧道会在收到心跳的瞬间被服务端
	// 关掉，重连会把隧道连接数顶到 2。
	select {
	case err := <-down:
		t.Fatalf("隧道在心跳之后断开: %v", err)
	case <-time.After(3 * time.Second):
	}
	if got := srv.Tunnels(); got != 1 {
		t.Errorf("隧道连接数 = %d，期望 1（重连说明链路被断过）", got)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("等待超时: %s", what)
}

var _ = errors.Is
