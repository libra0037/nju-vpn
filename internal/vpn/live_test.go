package vpn

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/config"
	"github.com/libra0037/nju-vpn/internal/dial"
)

// 真实服务端的实验阶梯。
//
// 这些用例默认跳过：跑一次会消耗账号的服务端配额，有的还会发短信，
// 所以必须显式打开。已有的单元测试用的是注入的假服务端，不需要联网。
//
//	export NJUVPON_LIVE_CONFIG=/tmp/njuvpn-lab.yaml
//	go test ./internal/vpn/ -run TestLiveLoginPage -v      # 免费：只取登录页
//	NJUVPON_LIVE_CONNECT=1 go test ./internal/vpn/ -run TestLiveConnect -v   # 花一条短信
//
// 阶梯的意义在于每一步都能单独定位故障：
//
//	login-page    真实 TLS + HTTP + 页面解析
//	connect       口令登录 → 二次验证 → token → query-ip → 流握手
//
// 连不上的时候，先确认前一级通过，再往后查。

// liveConfig 读取真实账号配置。没有设置环境变量时跳过。
func liveConfig(t *testing.T) *config.Config {
	t.Helper()
	path := os.Getenv("NJUVPON_LIVE_CONFIG")
	if path == "" {
		t.Skip("未设置 NJUVPON_LIVE_CONFIG，跳过真实服务端实验")
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("加载真实配置失败: %v", err)
	}
	return cfg
}

// liveClient 按配置构造真实的协议客户端。
func liveClient(t *testing.T, cfg *config.Config) *Client {
	t.Helper()
	dialFn, err := dial.New(cfg.Proxy)
	if err != nil {
		t.Fatalf("构造出站拨号失败: %v", err)
	}
	c := New(Options{
		Server:   cfg.ServerAddr(),
		DialAddr: cfg.DialAddr(),
		Dial:     dialFn,
	})
	t.Cleanup(c.CloseIdleConnections)

	if cfg.DialAddr() != "" {
		t.Logf("连接地址覆盖为 %s（协议层仍用 %s）", cfg.DialAddr(), cfg.ServerAddr())
	}
	return c
}

// TestLiveLoginPage 只取登录页：验证真实 TLS 握手、HTTP 往返与页面解析。
//
// 这一步不提交口令、不建立会话、不消耗短信配额，是最便宜的连通性验证。
// 它同时能确认新代码在真实服务端上的超时、deadline 与解析路径是对的。
func TestLiveLoginPage(t *testing.T) {
	cfg := liveConfig(t)
	client := liveClient(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	body, err := client.do(ctx, http.MethodGet, "/por/login_auth.csp?apiversion=1", nil, "")
	if err != nil {
		t.Fatalf("取登录页失败: %v", err)
	}
	t.Logf("登录页 %d 字节，耗时 %s", len(body), time.Since(start).Round(time.Millisecond))

	twfID, err := requireTag("web-login", body, "TwfID")
	if err != nil {
		t.Fatalf("登录页里没有 TwfID: %v", err)
	}
	if strings.TrimSpace(twfID) == "" {
		t.Fatal("登录页返回了空 TwfID")
	}
	t.Logf("TwfID: %s", redact(twfID))

	keyHex, err := requireTag("web-login", body, "RSA_ENCRYPT_KEY")
	if err != nil {
		t.Fatalf("登录页里没有 RSA 公钥: %v", err)
	}
	exp := "65537"
	if v, ok := tagValue(body, "RSA_ENCRYPT_EXP"); ok {
		exp = strings.TrimSpace(v)
	}
	pub, err := parsePublicKey("web-login", keyHex, exp)
	if err != nil {
		t.Fatalf("公钥解析失败: %v", err)
	}
	t.Logf("RSA 公钥 %d 位，指数 %d", pub.N.BitLen(), pub.E)
	if pub.N.BitLen() < 1024 {
		t.Errorf("服务端公钥只有 %d 位，异常", pub.N.BitLen())
	}

	if csrf, ok := tagValue(body, "CSRF_RAND_CODE"); ok {
		t.Logf("CSRF 码: %d 字节", len(strings.TrimSpace(csrf)))
	} else {
		t.Log("服务端未提供 CSRF 码（会按旧版本处理）")
	}
}

// TestLiveConnect 走完整链路：登录、二次验证、token、query-ip、流握手。
//
// 会触发一条短信，所以需要显式打开：
//
//	NJUVPON_LIVE_CONNECT=1 NJUVPON_LIVE_CONFIG=... go test -run TestLiveConnect -v
//
// 验证码从标准输入读；也可以先设 NJUVPON_LIVE_CODE 直接给。
func TestLiveConnect(t *testing.T) {
	if os.Getenv("NJUVPON_LIVE_CONNECT") != "1" {
		t.Skip("未设置 NJUVPON_LIVE_CONNECT=1（这一步会发短信），跳过")
	}
	cfg := liveConfig(t)
	client := liveClient(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	trace := &Trace{}
	opt := ConnectOptions{
		Username: cfg.Username,
		Password: cfg.Password,
		Trace:    trace,
	}

	start := time.Now()
	sess, err := client.Connect(ctx, opt)
	reportStages(t, trace, start)

	// 服务端要求二次验证：要验证码后在同一个会话里继续。
	if authErr, ok := AsAuthRequired(err); ok {
		t.Logf("服务端要求二次验证: %v", authErr.Kind)

		code := strings.TrimSpace(os.Getenv("NJUVPON_LIVE_CODE"))
		if code == "" {
			fmt.Fprint(os.Stderr, "请输入验证码: ")
			line, readErr := bufio.NewReader(os.Stdin).ReadString('\n')
			if readErr != nil && line == "" {
				t.Fatalf("读取验证码失败: %v", readErr)
			}
			code = strings.TrimSpace(line)
		}
		if code == "" {
			t.Fatal("验证码为空")
		}

		opt.TwfID = authErr.TwfID
		opt.Code = code
		opt.AuthKind = authErr.Kind
		trace = &Trace{}
		opt.Trace = trace

		start = time.Now()
		sess, err = client.Connect(ctx, opt)
		reportStages(t, trace, start)
	}

	// 无论成败，只要拿到了会话就必须登出，否则服务端名额不会释放。
	if sess != nil {
		defer func() {
			if closeErr := sess.Close(context.Background()); closeErr != nil {
				t.Errorf("登出失败（服务端可能留下占名额的会话）: %v", closeErr)
			} else {
				t.Log("已登出并释放服务端会话")
			}
		}()
	}
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}

	t.Logf("校园网地址: %s", sess.ClientIP())
	if sess.ClientIP() == "" {
		t.Error("没有拿到校园网地址")
	}

	// 流握手：建立下行流后立刻关闭，确认服务端接受我们的会话。
	start = time.Now()
	if err := sess.CheckTunnel(ctx); err != nil {
		t.Fatalf("流握手失败: %v", err)
	}
	t.Logf("下行流握手通过，耗时 %s", time.Since(start).Round(time.Millisecond))
}

// reportStages 打印各阶段耗时，失败时指出停在哪一步。
func reportStages(t *testing.T, trace *Trace, start time.Time) {
	t.Helper()
	for _, s := range trace.Stages() {
		result := "OK"
		if s.Err != nil {
			result = s.Err.Error()
		}
		t.Logf("  %-20s %-10s %s", s.Name, s.Duration.Round(time.Millisecond), result)
	}
	t.Logf("  合计 %s", time.Since(start).Round(time.Millisecond))
}
