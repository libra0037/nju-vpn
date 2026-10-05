package ztna

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/l3"
	"github.com/libra0037/nju-vpn/internal/ztnatest"
)

// TestSendReadsFlowStateUnderLock 回归：上行每包的判定必须在流表的锁里取。
//
// 以前 Send 拿到共享的 *flow 指针、在锁外读 state，而 completeAuth 跑在
// 隧道读协程里改同一个字段：跑 -race 会报数据竞争（把 sendState 退回
// “get 之后在锁外读 state”即复现）。实际后果是失败流的判定可能读到陈旧值，
// 包被塞进缓存直到上限。
func TestSendReadsFlowStateUnderLock(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	// net.Pipe 是同步的：没人在另一头读，写入会一直阻塞。
	go func() { _, _ = io.Copy(io.Discard, server) }()

	table, err := parseResourceTable([]byte(`{"code":0,"data":{"appList":{"data":{"appInfo":[{"apps":[
		{"id":"app-a","nodeGroupId":"groupWan","accessModel":"L3VPN","addressList":[
			{"protocol":"tcp","port":"443","host":"10.1.0.0/16"}]}]}],"config":{"nodeGroupConf":{
		"majorNodeGroup":{"id":"groupWan"},"nodeGroupList":[{"id":"groupWan","addressInfo":[]}]}}}}}}`), "vpn.test")
	if err != nil {
		t.Fatal(err)
	}

	tc := &tunnelConn{
		node:     "test-node",
		mtu:      1400,
		conn:     client,
		ep:       l3.New(),
		flows:    newFlowTable(),
		table:    table,
		authWake: make(chan struct{}, 1),
		logf:     func(string, ...any) {},
	}
	pkt := ipv4TCP("10.66.66.2", "10.1.2.3", 40000, 443, nil)

	// 首包建流并缓存首包。
	if err := tc.Send(pkt); err != nil {
		t.Fatalf("首包应当被缓存而不是失败: %v", err)
	}
	flows := tc.flows.pendingAuth(1)
	if len(flows) != 1 {
		t.Fatalf("首包没有建流，pendingAuth = %d 条", len(flows))
	}
	authID := flows[0].authID // 建流时写一次，之后不再变

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 300; i++ {
			_ = tc.Send(pkt)
		}
	}()
	// 另一侧（隧道读协程的角色）把这条流判成失败。
	for i := 0; i < 300; i++ {
		tc.flows.completeAuth(authID, "", errors.New("鉴权被拒"))
	}
	<-done

	if err := tc.Send(pkt); err == nil {
		t.Fatal("鉴权失败的流仍被放行")
	}
}

// stallOptions 指向一个“TCP/TLS 都通、但收下握手请求后不再回帧”的节点。
func stallOptions(t *testing.T, timeout time.Duration) tunnelOptions {
	t.Helper()
	srv := newFake(t, ztnatest.Options{StallTunnelHandshake: true})
	return tunnelOptions{
		Pins:             newNodeSPKIPins([][32]byte{srv.SPKIPin()}),
		Node:             srv.Addr(),
		Server:           "vpn.test",
		Dial:             srv.Dial,
		Table:            &resourceTable{},
		Endpoint:         l3.New(),
		SID:              "sid-cookie-value",
		DeviceID:         "device-test-1",
		SignKey:          []byte("0123456789abcdef"),
		HandshakeTimeout: timeout,
		MTU:              1400,
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

// TestAppendStreamCapsBuffer 验证下行累计缓冲有上限。
//
// 对端每帧都"比声明的少一字节"时，切剩的半包会一直攒下去：心跳判死之前有
// 45 秒窗口，期间内存单向增长。判据是超过上限即报协议错误，而不是继续攒。
func TestAppendStreamCapsBuffer(t *testing.T) {
	stream, err := appendStream(nil, make([]byte, maxStreamBytes-1))
	if err != nil {
		t.Fatalf("上限之内的累计不该报错: %v", err)
	}
	_, err = appendStream(stream, make([]byte, 2))
	if err == nil {
		t.Fatal("超过上限应当报协议错误")
	}
	var pe *ProtocolError
	if !errors.As(err, &pe) {
		t.Fatalf("应当是协议错误，得到 %T: %v", err, err)
	}

	// 正常的一帧（声明长度与实际一致）不该被上限误伤。
	if _, err := appendStream(nil, make([]byte, 1500)); err != nil {
		t.Fatalf("正常帧不该报错: %v", err)
	}
}
