package ztna

import (
	"bufio"
	"io"
	"net"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/l3"
)

// TestHeartbeatGapOnlyClearedOnReceivedFrames 验证失联计数只由“收到服务端帧”
// 清零，写成功不算。
//
// 对端静默消失（NAT、防火墙、断电）时本地写入照样成功；只要客户端持续有
// 命中资源表的流量，老的实现就会一直把计数清回 0，15 秒乘 3 的判死形同虚设，
// 只能等内核 TCP 重传耗尽（分钟级）才报错。
func TestHeartbeatGapOnlyClearedOnReceivedFrames(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	tc := &tunnelConn{
		node:     "test-node",
		conn:     client,
		ep:       l3.New(),
		flows:    newFlowTable(),
		table:    &resourceTable{},
		closeCh:  make(chan struct{}),
		authWake: make(chan struct{}, 1),
		logf:     t.Logf,
	}
	// net.Pipe 是同步的：没有对端读，write 会一直阻塞。这里把服务端方向
	// 的字节读掉，模拟“对端还在收，但什么都不回”。
	go func() { _, _ = io.Copy(io.Discard, server) }()

	tc.setVIP(net.ParseIP("172.16.0.9"))
	tc.heartbeatGap.Store(2)

	// 写成功不清零。
	if err := tc.write(encodeHeartbeat()); err != nil {
		t.Fatalf("写心跳: %v", err)
	}
	if got := tc.heartbeatGap.Load(); got != 2 {
		t.Fatalf("写成功之后计数 = %d，期望仍是 2", got)
	}

	// 收到一个服务端帧才清零。
	tc.r = bufio.NewReader(client)
	go tc.readLoop()
	if _, err := server.Write([]byte{Version, cmdHeartbeatResp, 0, 0}); err != nil {
		t.Fatalf("发心跳响应: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if tc.heartbeatGap.Load() == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("收到服务端帧之后计数 = %d，期望 0", tc.heartbeatGap.Load())
}

// TestParseVIPListPayload 验证地址列表的几种形态都能取出来，取不到时返回空。
func TestParseVIPListPayload(t *testing.T) {
	const (
		formDataVIP   = `{"code":0,"data":{"vip":"172.16.0.9"}}`
		formDualStack = `{"data":{"vip":"172.16.0.9","vip6":"2001:db8::1"}}`
		formTopVIP    = `{"vip":"172.16.1.1"}`
		formArray     = `{"data":["172.16.2.1","10.0.0.1"]}`
		formNested    = `{"data":{"vips":[["172.16.3.1"],{"ip":"172.16.3.2"}]}}`
		formNoAddr    = `{"data":{"vip":"","hint":"none"}}`
	)
	cases := []struct {
		name    string
		payload string
		want    []string
	}{
		{"data.vip 形态", formDataVIP, []string{"172.16.0.9"}},
		{"同时含 IPv6", formDualStack, []string{"172.16.0.9", "2001:db8::1"}},
		{"顶层 vip", formTopVIP, []string{"172.16.1.1"}},
		{"数组", formArray, []string{"172.16.2.1", "10.0.0.1"}},
		{"嵌套结构", formNested, []string{"172.16.3.1", "172.16.3.2"}},
		{"没有地址", formNoAddr, nil},
		{"不是 JSON", "not-json", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseVIPListPayload([]byte(c.payload))
			if len(got) != len(c.want) {
				t.Fatalf("解析出 %v，期望 %v", got, c.want)
			}
			for i := range got {
				if got[i].String() != c.want[i] {
					t.Errorf("第 %d 个地址 = %v，期望 %v", i, got[i], c.want[i])
				}
			}
		})
	}
}
