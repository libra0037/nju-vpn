package ztna

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/l3"
	"github.com/libra0037/nju-vpn/internal/ztnatest"
)

// 使用真实 TLS 验证同一控制面路径；信任注入不能关闭名称验证。
func TestControlPlaneVerifiesCertificate(t *testing.T) {
	srv := newFake(t, ztnatest.Options{})
	for _, tc := range []struct {
		name, server string
		roots        *x509.CertPool
		want         string
	}{
		{"受控信任", "vpn.test", srv.RootCAs(), ""},
		{"系统信任不接受测试证书", "vpn.test", nil, "authority"},
		{"空信任池", "vpn.test", x509.NewCertPool(), "authority"},
		{"名称不匹配", "other.test", srv.RootCAs(), "hostname"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := New(Options{
				NodeSPKIPins: [][32]byte{srv.SPKIPin()}, ControlRootCAs: tc.roots,
				Server: tc.server, DialAddr: srv.Addr(), Dial: srv.Dial,
				Username: testUser, Password: testPass, DeviceID: "device-test-1", MTU: 1500, Logf: t.Logf,
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			sess, err := client.Connect(ctx, ConnectOptions{})
			if sess != nil {
				t.Cleanup(func() { sess.Close(context.Background()) })
			}
			if tc.want == "" {
				if err != nil || sess.ClientIP() == nil {
					t.Fatalf("可信证书应成功: %v", err)
				}
				return
			}
			var certErr *tls.CertificateVerificationError
			if !errors.Is(err, ErrControlTLS) || !errors.As(err, &certErr) {
				t.Fatalf("须保留 TLS 验证阶段和底层错误，得到 %v", err)
			}
			var authority x509.UnknownAuthorityError
			var hostname x509.HostnameError
			if tc.want == "authority" && !errors.As(err, &authority) || tc.want == "hostname" && !errors.As(err, &hostname) {
				t.Fatalf("证书拒绝类别不符: %v", err)
			}
			if sess == nil || !sess.closed || sess.active != nil {
				t.Fatal("失败会话未清理")
			}
		})
	}
}

// TestDialTunnelRejectsUnpinnedNode 验证数据面的指纹校验确实接在握手上：
// 指纹对不上的节点会被拒，错误里带上观测值供人确认。
func TestDialTunnelRejectsUnpinnedNode(t *testing.T) {
	srv := newFake(t, ztnatest.Options{})
	opts := tunnelOptions{
		Node:     srv.Addr(),
		Server:   "vpn.test",
		Dial:     srv.Dial,
		Table:    &resourceTable{},
		Endpoint: l3.New(),
		SID:      "sid-cookie-value",
		DeviceID: "device-test-1",
		SignKey:  []byte("0123456789abcdef"),
		Logf:     t.Logf,
		MTU:      1500,
		// 严格模式 + 一个对不上的指纹：陌生节点不再被“首次记录”放过。
		Pins: newNodeSPKIPins([][sha256.Size]byte{sha256.Sum256([]byte("other"))}),
	}

	conn, err := dialTunnel(context.Background(), opts)
	if err == nil {
		_ = conn.Close()
		t.Fatal("指纹对不上的节点应当被拒绝")
	}
	if !errors.Is(err, ErrNodeUntrusted) {
		t.Fatalf("错误应当告诉用户把观测到的指纹填到哪，得到 %v", err)
	}
}
