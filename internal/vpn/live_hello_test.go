package vpn

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// TestLiveTunnelHello 验证隧道那个刻意畸形的 ClientHello 能被服务端接受。
//
// 这一步不涉及账号、不建会话、不发短信：握手完成后立刻关闭连接，
// 服务端连流协议的第一个字节都没见到。它验证的是整个协议里最脆弱的一环——
// TLS 1.1 + RC4-SHA + 以 L3IP 开头的 SessionId，服务端靠这些特征决定
// 把连接当成隧道还是当成 Web 登录。
//
// 同时做一次反向对照：用普通 ClientHello 连同一地址，观察服务端是否拒绝。
// 这一条只记录结果不作为断言——反例的表现形式（握手报错还是直接断开）
// 由服务端实现决定，写死了反而会在服务端调整时误报。
func TestLiveTunnelHello(t *testing.T) {
	cfg := liveConfig(t)
	client := liveClient(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	// 正向：隧道 ClientHello 必须能完成握手。
	start := time.Now()
	conn, err := client.tunnelTLS(ctx)
	if err != nil {
		t.Fatalf("建立隧道连接失败: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatalf("设置超时失败: %v", err)
	}

	hs, ok := conn.(interface{ Handshake() error })
	if !ok {
		t.Fatal("隧道连接不支持显式握手")
	}
	if err := hs.Handshake(); err != nil {
		t.Fatalf("隧道 ClientHello 被服务端拒绝: %v", err)
	}
	t.Logf("隧道 ClientHello 握手成功，耗时 %s", time.Since(start).Round(time.Millisecond))

	// 对照：同一个地址上的普通 TLS 连接。它会握手成功——443 端口本来
	// 就要同时服务 Web 登录，所以这条只说明"端口是复用的"，不说明分流方式。
	ctrl, err := client.portalTLS(ctx)
	if err != nil {
		t.Fatalf("建立对照连接失败: %v", err)
	}
	defer ctrl.Close()
	_ = ctrl.SetDeadline(time.Now().Add(20 * time.Second))
	if hs, ok := ctrl.(interface{ Handshake() error }); ok {
		if err := hs.Handshake(); err != nil {
			t.Errorf("普通 TLS 连接失败（Web 登录路径应该能用）: %v", err)
		} else {
			t.Log("对照：普通 TLS 握手成功（Web 登录路径正常）")
		}
	}
}

// TestLiveTunnelHelloDiscriminator 验证"以 L3IP 开头"确实是服务端的判别位。
//
// 做法是造一个和隧道 hello 只差一个字段的连接，逐个排除：
//
//	版本/套件相同，SessionId 换成非 L3IP  → 如果被拒，说明 L3IP 是判别位
//	SessionId 是 L3IP，版本换成 TLS 1.2   → 如果被拒，说明版本也参与判别
//
// 服务端拒绝的形式可能是握手报错，也可能是握手通过后在应用层断开，
// 所以这里不仅看握手结果，还额外发一个字节看连接是否还活着。
func TestLiveTunnelHelloDiscriminator(t *testing.T) {
	cfg := liveConfig(t)
	client := liveClient(t, cfg)

	cases := []struct {
		name      string
		version   uint16
		sessionID func() []byte
	}{
		{"SessionId 不是 L3IP", utls.VersionTLS11, func() []byte {
			id := make([]byte, 32)
			copy(id, "NOPE")
			return id
		}},
		{"版本换成 TLS 1.2", utls.VersionTLS12, tunnelHelloSessionID},
		{"SessionId 为空", utls.VersionTLS11, func() []byte { return nil }},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			conn, err := client.DialContext(ctx)
			if err != nil {
				t.Fatalf("建 TCP 连接失败: %v", err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

			uconn := utls.UClient(conn, &utls.Config{InsecureSkipVerify: true}, utls.HelloCustom)
			random := make([]byte, 32)
			if _, err := rand.Read(random); err != nil {
				t.Fatal(err)
			}
			uconn.SetClientRandom(random)
			uconn.SetTLSVers(c.version, c.version, nil)
			uconn.HandshakeState.Hello.Vers = c.version
			uconn.HandshakeState.Hello.CipherSuites = tunnelHelloCipherSuites()
			uconn.HandshakeState.Hello.CompressionMethods = tunnelHelloCompression()
			uconn.HandshakeState.Hello.SessionId = c.sessionID()

			if err := uconn.Handshake(); err != nil {
				t.Logf("握手被拒: %v", err)
				return
			}

			// 握手过了，再看应用层是否还活着。
			if _, err := uconn.Write([]byte{0x00, 0x00, 0x00, 0x00}); err != nil {
				t.Logf("握手通过但写失败: %v", err)
				return
			}
			buf := make([]byte, 8)
			n, err := uconn.Read(buf)
			t.Logf("握手通过且应用层存活（读到 %d 字节，err=%v）", n, err)
		})
	}
}
