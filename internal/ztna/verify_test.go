package ztna

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/l3"
	"github.com/libra0037/nju-vpn/internal/ztnatest"
)

// TestControlPlaneVerifiesCertificate 验证控制面默认走系统信任链：假服务端的
// 自签证书必须被拒绝。这条通道走的是口令与短信验证码，是 M12 里最要紧的一半。
func TestControlPlaneVerifiesCertificate(t *testing.T) {
	srv := newFake(t, ztnatest.Options{})
	client, newErr := New(Options{
		NodeSPKIPins: [][32]byte{srv.SPKIPin()},
		Server:       "vpn.test",
		DialAddr:     srv.Addr(),
		Dial:         srv.Dial,
		Username:     testUser,
		Password:     testPass,
		DeviceID:     "device-test-1",
		Logf:         t.Logf,
	})

	if newErr != nil {
		t.Fatal(newErr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sess, err := client.Connect(ctx, ConnectOptions{})
	if sess != nil {
		_ = sess.Close(context.Background())
	}
	if err == nil {
		t.Fatal("自签证书应当被拒绝（控制面默认走系统信任链）")
	}
	var certErr *tls.CertificateVerificationError
	if !errors.As(err, &certErr) {
		t.Fatalf("错误应当指向证书校验，得到 %v", err)
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
