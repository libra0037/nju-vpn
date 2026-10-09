package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/config"
	wg "github.com/libra0037/nju-vpn/internal/wireguard"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gopkg.in/yaml.v3"
)

const (
	targetIP   = "192.0.2.1"
	targetHTTP = targetIP + ":18080"
	targetUDP  = targetIP + ":18081"
)

const testRunID = "0123456789abcdef0123456789abcdef"

// 对侧也是真实 WireGuard 设备。HTTP 与 UDP 固定样例只在内存网络栈监听，
// 系统网络仅承载加密的回环 UDP；无法从系统 HTTP 绕过 WireGuard 得到 PASS。
func testPeer(t *testing.T, truncate bool, wrap func(tun.Device) tun.Device) *directPeer {
	t.Helper()
	serverKey, err := wg.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := wg.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	clientPub, err := clientKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	tun, stack, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(targetIP)}, nil, mtu)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), &device.Logger{
		Verbosef: func(string, ...any) {}, Errorf: func(string, ...any) {},
	})
	t.Cleanup(dev.Close)
	uapi := fmt.Sprintf("private_key=%s\nlisten_port=0\nreplace_peers=true\npublic_key=%s\nallowed_ip=10.66.66.2/32\n",
		hex.EncodeToString(serverKey[:]), hex.EncodeToString(clientPub[:]))
	if err := dev.IpcSet(uapi); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	text, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	port := 0
	for _, line := range strings.Split(text, "\n") {
		if value, ok := strings.CutPrefix(line, "listen_port="); ok {
			port, err = strconv.Atoi(value)
		}
	}
	if err != nil || port == 0 {
		t.Fatal("没有取得对侧回环端口")
	}
	listener, err := stack.ListenTCPAddrPort(netip.MustParseAddrPort(targetHTTP))
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{ReadHeaderTimeout: time.Second, MaxHeaderBytes: 4096, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Njuvpn-Test-Id") != testRunID {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch r.URL.Path {
		case "/health":
			w.Header().Set("Content-Length", "20")
			io.WriteString(w, "njuvpn-release-test\n")
		case "/slow-blob":
			w.Header().Set("Content-Length", "8388608")
			if truncate {
				w.Write([]byte{0, 1, 2, 3, 4})
				return
			}
			block := make([]byte, 65536)
			for i := range block {
				block[i] = byte(i)
			}
			for i := 0; i < 128; i++ {
				if _, err := w.Write(block); err != nil {
					return
				}
			}
		case "/echo":
			body, err := io.ReadAll(io.LimitReader(r.Body, 1048577))
			if err != nil || len(body) != 1048576 || r.Method != "POST" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Length", "1048576")
			w.Write(body)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})}
	httpDone := make(chan struct{})
	go func() { defer close(httpDone); server.Serve(listener) }()
	t.Cleanup(func() { server.Close(); <-httpDone })
	udp, err := stack.ListenUDPAddrPort(netip.MustParseAddrPort(targetUDP))
	if err != nil {
		t.Fatal(err)
	}
	udpDone := make(chan struct{})
	go func() {
		defer close(udpDone)
		body := make([]byte, 4097)
		for {
			n, address, err := udp.ReadFrom(body)
			if err != nil {
				return
			}
			reply := body[:n]
			if strings.HasPrefix(string(reply), "NJUVPN-SHA256:") {
				digest := sha256.Sum256(reply)
				reply = digest[:]
			}
			if _, err := udp.WriteTo(reply, address); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { udp.Close(); <-udpDone })
	peer, err := makePeer(&config.Config{WireGuard: config.WireGuard{
		PrivateKey: serverKey.String(), PeerAddress: "10.66.66.2", ListenPort: port,
	}}, clientKey, netip.MustParseAddr(targetIP), wrap)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(peer.dev.Close)
	return peer
}

func TestDirectPeerCarriesVerifiedHTTPAndUDP(t *testing.T) {
	peer := testPeer(t, false, nil)
	// 双核主机的离线双栈用例已观测到超过十秒的传输。本例校验正文与
	// 握手，沿用工具的传输预算并限制整轮，不把十秒当作吞吐契约。
	ctx, cancel := context.WithTimeout(t.Context(), transferBudget)
	defer cancel()
	report := probe(ctx, peer, testRunID, probeBudgets{request: 10 * time.Second, transfer: transferBudget})
	if !report.Passed || !report.HandshakeSeen || len(report.Checks) != 5 {
		t.Fatalf("直接握手或固定样例未通过: %+v", report)
	}
	for i, size := range []int64{20, 8388608, 1048576, 32, 1372} {
		if !report.Checks[i].Passed || report.Checks[i].Bytes != size {
			t.Fatalf("样例 %d 收包不完整: %+v", i, report.Checks[i])
		}
	}
}

func TestTruncatedResponseIsFailureWithReceivedByteCount(t *testing.T) {
	peer := testPeer(t, true, nil)
	report := probe(context.Background(), peer, testRunID, probeBudgets{request: 10 * time.Second, transfer: 10 * time.Second})
	if report.Passed || !report.HandshakeSeen || len(report.Checks) != 2 {
		t.Fatalf("截断响应错误接受: %+v", report)
	}
	result := report.Checks[1]
	if result.Passed || result.Error != "unexpected-eof" || result.Bytes != 5 || result.HTTPStatus != 200 {
		t.Fatalf("截断响应诊断错误: %+v", result)
	}
}

func TestCancelledRequestHasNoUnboundedWait(t *testing.T) {
	peer := testPeer(t, false, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := probeHTTP(ctx, peer, testRunID, time.Second, "health", "GET", "/health", "", 20)
	if result.Passed || result.Error != "cancelled" || result.ElapsedMS > 500 {
		t.Fatalf("取消没有立即生效: %+v", result)
	}
}

func TestPrepareLeavesSourceAndPinsUnchanged(t *testing.T) {
	serverKey, err := wg.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Server: "test.invalid", Username: "release-test", Password: "secret-never-printed",
		DeviceID: "test-device", Proxy: "socks5://test.invalid:1000",
		WireGuard:            config.WireGuard{Enabled: true, MTU: 1400, ListenPort: 51821, ListenHost: "loopback", PeerAddress: "10.66.66.2", PrivateKey: serverKey.String()},
		PinnedNodeSPKISHA256: []string{base64.StdEncoding.EncodeToString(make([]byte, 32))},
	}
	body, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "original.yaml")
	if err := os.WriteFile(source, body, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.LoadForClient(source)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "private-direct")
	if err := prepare(loaded, out); err != nil {
		t.Fatal(err)
	}
	prepared, err := config.LoadForClient(filepath.Join(out, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := readKey(filepath.Join(out, "peer.key"))
	if err != nil {
		t.Fatal(err)
	}
	public, err := key.PublicKey()
	if err != nil || public.String() != prepared.WireGuard.PeerPublicKey {
		t.Fatal("生成的对端身份不匹配")
	}
	if prepared.DeviceID != loaded.DeviceID || prepared.Password != loaded.Password || prepared.Proxy != loaded.Proxy ||
		prepared.WireGuard.PrivateKey != loaded.WireGuard.PrivateKey ||
		strings.Join(prepared.PinnedNodeSPKISHA256, ",") != strings.Join(loaded.PinnedNodeSPKISHA256, ",") {
		t.Fatal("独立配置丢失原身份或 TLS 策略")
	}
	if after, err := os.ReadFile(source); err != nil || string(after) != string(body) {
		t.Fatal("原配置被改动")
	}
	if err := prepare(loaded, out); err == nil {
		t.Fatal("覆盖了已有私有目录")
	}
}

func TestProxyUploadUsesOnlySpecifiedProxyAndFixedPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.String() != "http://192.0.2.1:18080/echo" ||
			r.ContentLength != 1048576 || r.Header.Get("X-Njuvpn-Test-Id") != testRunID ||
			r.Header.Get("Content-Type") != "application/octet-stream" || r.Header.Get("Expect") != "100-continue" || r.UserAgent() != "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1048577))
		if err != nil || len(body) != 1048576 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		for i, b := range body {
			if b != byte(i%256) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		}
		w.Header().Set("Content-Length", "1048576")
		w.Write(body)
	}))
	t.Cleanup(server.Close)
	proxy, err := localProxyURL(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	// 即使机器上有其他出站代理，也只能拨指定的回环测试入口。
	t.Setenv("HTTP_PROXY", "http://must-not-dial.invalid:1")
	t.Setenv("NO_PROXY", "*")
	result := probeProxyUpload(context.Background(), proxy, netip.MustParseAddr(targetIP), testRunID, 5*time.Second)
	if !result.Passed || result.Bytes != 1048576 || result.HTTPStatus != 200 {
		t.Fatalf("代理路径或固定上传错误: %+v", result)
	}
}

func TestProxyUploadRejectsHTTPErrorAndUnsafeProxy(t *testing.T) {
	for _, value := range []string{"http://remote.invalid:80", "http://192.0.2.1:80", "http://127.0.0.1:0", "http://user:secret@127.0.0.1:80", "http://127.0.0.1:80/path", "http://127.0.0.1:80?q=secret", "https://127.0.0.1:80", strings.Repeat("x", 257)} {
		if _, err := localProxyURL(value); err == nil {
			t.Errorf("接受了无效代理入口")
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(server.Close)
	proxy, err := localProxyURL(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	result := probeProxyUpload(context.Background(), proxy, netip.MustParseAddr(targetIP), testRunID, time.Second)
	if result.Passed || result.HTTPStatus != 502 || result.Error != "http-status-or-length" {
		t.Fatalf("代理 502 被接受或分类错误: %+v", result)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result = probeProxyUpload(ctx, proxy, netip.MustParseAddr(targetIP), testRunID, time.Second)
	if result.Passed || result.Error != "cancelled" || result.ElapsedMS > 500 {
		t.Fatalf("代理上传取消未生效: %+v", result)
	}
	path := filepath.Join(t.TempDir(), "result.json")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeResult(path, proxyUploadReport{RunID: testRunID}); err == nil {
		t.Fatal("结果覆盖了已有文件")
	}
	if body, err := os.ReadFile(path); err != nil || string(body) != "keep" {
		t.Fatal("拒绝覆盖后原文件改变")
	}
}
