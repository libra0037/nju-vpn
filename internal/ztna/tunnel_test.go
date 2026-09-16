package ztna

import (
	"bufio"
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/l3"
	"github.com/libra0037/nju-vpn/internal/ztnatest"
)

// stallOptions 指向一个“TCP/TLS 都通、但收下握手请求后不再回帧”的节点。
func stallOptions(t *testing.T, timeout time.Duration) tunnelOptions {
	t.Helper()
	srv := newFake(t, ztnatest.Options{StallTunnelHandshake: true})
	return tunnelOptions{
		Node:             srv.Addr(),
		Server:           "vpn.test",
		Dial:             srv.Dial,
		Table:            &resourceTable{},
		Endpoint:         l3.New(),
		SID:              "sid-cookie-value",
		DeviceID:         "device-test-1",
		SignKey:          []byte("0123456789abcdef"),
		HandshakeTimeout: timeout,
		Logf:             t.Logf,
	}
}

// TestDialTunnelHandshakeTimeout 验证“TLS 通了但节点不再回帧”不会把调用方
// 永久卡住：握手阶段有固定上限，到点自己收场。
//
// 没有上限时这一次读会一直挂着，ctx 取消也打断不了，守护进程的命令通道
// （stop / status）跟着一起卡死——而杀进程会跳过登出。
func TestDialTunnelHandshakeTimeout(t *testing.T) {
	opts := stallOptions(t, 300*time.Millisecond)

	start := time.Now()
	conn, err := dialTunnel(context.Background(), opts)
	elapsed := time.Since(start)

	if err == nil {
		_ = conn.Close()
		t.Fatal("节点不回帧时应当报错，实际握手成功")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("握手用了 %v 才失败，说明固定上限没生效（%v）", elapsed, err)
	}
	if elapsed < 200*time.Millisecond {
		t.Fatalf("握手 %v 就失败了，不像是等到了期限: %v", elapsed, err)
	}
}

// TestDialTunnelHandshakeHonorsCancel 验证 ctx 取消能立刻打断握手中的读，
// 而不是等满默认上限。
func TestDialTunnelHandshakeHonorsCancel(t *testing.T) {
	opts := stallOptions(t, 0) // 用默认上限
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		time.Sleep(150 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	conn, err := dialTunnel(ctx, opts)
	elapsed := time.Since(start)

	if err == nil {
		_ = conn.Close()
		t.Fatal("ctx 取消之后握手应当失败")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("取消之后用了 %v 才返回，说明阻塞中的读没被打断（%v）", elapsed, err)
	}
}

// TestReadHandshakeRejectsEndlessFrames 验证握手帧数有上限：对端一直刷空信封
// 时读循环必须收场，而不是无限跑下去。
func TestReadHandshakeRejectsEndlessFrames(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{Version, methodHandshake})
	for i := 0; i < handshakeFrameLimit+5; i++ {
		buf.Write([]byte{envelopeVersion, 0, 0, 0})
	}

	_, err := readHandshake(bufio.NewReader(&buf))
	if err == nil {
		t.Fatal("无限刷帧时应当报错")
	}
	if !strings.Contains(err.Error(), "握手帧数超过上限") {
		t.Fatalf("错误应当是帧数超限，得到 %v", err)
	}
}
