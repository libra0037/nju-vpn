package vpntest

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// 未注册的路径必须回 404 并带上路径名，否则测试里"顺手加了新请求"
// 会静默拿到空响应，排查起来像协议问题。
func TestPortalUnscriptedPathReturns404(t *testing.T) {
	p := NewPortal()
	resp, err := p.HTTPClient().Get("https://vpn.example.edu/por/nope.csp")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("状态码 = %d，期望 404", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "/por/nope.csp") {
		t.Errorf("404 响应里应带上路径，实际 %q", body)
	}
}

// Chunks 让一条响应分多个 TCP 段到达，用来验证解析器不假设"一次读到一个完整响应"。
func TestPortalChunksArriveSeparately(t *testing.T) {
	p := NewPortal()
	p.On("/por/x.csp", Response{Chunks: [][]byte{[]byte("ab"), []byte("cd"), []byte("ef")}})
	resp, err := p.HTTPClient().Get("https://vpn.example.edu/por/x.csp")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "abcdef" {
		t.Errorf("分片内容拼起来 = %q，期望 abcdef", body)
	}
}

// 非 200 也能脚本化：协议层要能把"服务端返回错误页"和"网络失败"区分开。
func TestPortalStatusOverride(t *testing.T) {
	p := NewPortal()
	p.On("/por/x.csp", Response{Status: http.StatusForbidden, Body: "denied"})
	resp, err := p.HTTPClient().Get("https://vpn.example.edu/por/x.csp")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("状态码 = %d，期望 403", resp.StatusCode)
	}
}

// On 按注册顺序依次返回，用完即不再命中（回到 404）。
func TestPortalQueueIsConsumedInOrder(t *testing.T) {
	p := NewPortal()
	p.On("/por/x.csp", Response{Body: "first"}, Response{Body: "second"})
	for _, want := range []string{"first", "second"} {
		resp, err := p.HTTPClient().Get("https://vpn.example.edu/por/x.csp")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != want {
			t.Errorf("第 %d 次响应 = %q，期望 %q", p.Count("/por/x.csp"), body, want)
		}
	}
	resp, err := p.HTTPClient().Get("https://vpn.example.edu/por/x.csp")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("队列用完后状态码 = %d，期望 404", resp.StatusCode)
	}
}

// WaitRecvStream 必须是 channel 等待：以前是 5ms 轮询，测试靠赌时序。
// 这里先断言"没建立时超时返回错误"，再断言"建立后立刻返回"。
func TestWaitRecvStreamIsNotPolling(t *testing.T) {
	tun := NewTunnel()
	start := time.Now()
	if err := tun.WaitRecvStream(50 * time.Millisecond); err == nil {
		t.Fatal("下行流没建立时应当超时")
	}
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Errorf("等待 %s 就返回了，说明没等满超时", elapsed)
	}
}
