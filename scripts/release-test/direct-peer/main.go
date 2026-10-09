// 仅用于发布前测试：直接 WireGuard 对端，不创建网卡或系统路由。
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	requestBudget = 30 * time.Second
	// 公网出站实测限速 2 Mbit/s；8 MiB 正文已需 33.6 秒，另留协议与鉴权预算。
	transferBudget = 90 * time.Second
	mtu            = 1400
	downloadSize   = 8 * 1024 * 1024
	uploadSize     = 1024 * 1024
	httpPort       = 18080
	udpPort        = 18081
	// 独立的 Python bytes(range(256)) 样例给出摘要，不由校验路径产生期望值。
	downloadHash = "7d212b9c884f5c77896de960ae17cc341cda43b14d6a971f34ca29ebd4badf7f"
	uploadHash   = "fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83"
)

func main() {
	if err := run(); err != nil {
		// 错误仅是本工具的固定类别；底层路径、地址、密钥和口令不输出。
		fmt.Fprintln(os.Stderr, "直接对端测试:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) > 1 && strings.HasPrefix(os.Args[1], "campus-") {
		return runCampus(os.Args[1], os.Args[2:])
	}
	if len(os.Args) > 1 && os.Args[1] == "socks" {
		return runSOCKS(os.Args[2:])
	}
	if len(os.Args) > 1 && os.Args[1] == "resilience" {
		return runResilience(os.Args[2:])
	}
	if len(os.Args) < 2 || (os.Args[1] != "prepare" && os.Args[1] != "run" && os.Args[1] != "packet-check" && os.Args[1] != "upload-proxy" && os.Args[1] != "log-summary") {
		return errors.New("用法: test-peer prepare|run|packet-check|upload-proxy|log-summary|resilience|socks；参数见测试说明")
	}
	command := os.Args[1]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", "", "测试配置")
	out := flags.String("out", "", "新的私有目录")
	keyPath := flags.String("key", "", "对端私钥文件")
	resultPath := flags.String("result", "", "脱敏流量结果")
	proxyAddress := flags.String("proxy", "", "回环 HTTP 代理入口")
	runID := flags.String("run-id", "", "请求关联标识")
	if err := flags.Parse(os.Args[2:]); err != nil || flags.NArg() != 0 {
		return errors.New("参数无效")
	}
	if command == "log-summary" {
		if *path == "" || *resultPath == "" || *proxyAddress != "" || *out != "" || *keyPath != "" || *runID != "" {
			return errors.New("日志摘要参数无效")
		}
		cfg, err := config.LoadForClient(*path)
		if err != nil {
			return errors.New("日志摘要配置无效")
		}
		result, err := collectLogSummary(cfg.SourcePath())
		if err != nil {
			return err
		}
		return writeResult(*resultPath, result)
	}
	if command == "upload-proxy" {
		target, err := targetFromEnvironment()
		if err != nil {
			return err
		}
		proxy, err := localProxyURL(*proxyAddress)
		if err != nil || *resultPath == "" || !validRunID(*runID) || *path != "" || *out != "" || *keyPath != "" {
			return errors.New("代理上传参数无效；只允许无凭据的 IPv4 回环 HTTP 入口")
		}
		result := probeProxyUpload(context.Background(), proxy, target, *runID, transferBudget)
		if err := writeResult(*resultPath, proxyUploadReport{RunID: *runID, Passed: result.Passed, Check: result}); err != nil {
			return err
		}
		if !result.Passed {
			return errors.New("代理上传校验失败，详见脱敏结果")
		}
		return nil
	}
	if *path == "" || *proxyAddress != "" {
		return errors.New("参数无效")
	}
	cfg, err := config.LoadForClient(*path)
	if err != nil || !cfg.WireGuard.Enabled || cfg.WireGuard.MTU != mtu || (cfg.WireGuard.ListenHost != "" && cfg.WireGuard.ListenHost != "loopback") {
		return errors.New("配置无效；要求 MTU 1400、loopback 监听")
	}
	if command == "prepare" {
		if *out == "" {
			return errors.New("缺少新目录")
		}
		return prepare(cfg, *out)
	}
	target, err := targetFromEnvironment()
	if err != nil {
		return err
	}
	if *keyPath == "" || *resultPath == "" || !validRunID(*runID) {
		return errors.New("缺少私钥、结果文件或有效关联标识")
	}
	key, err := readKey(*keyPath)
	if err != nil {
		return errors.New("对端私钥文件无效")
	}
	pub, err := key.PublicKey()
	if err != nil || pub.String() != cfg.WireGuard.PeerPublicKey {
		return errors.New("对端私钥与测试配置的公钥不匹配")
	}
	var observer *packetTUN
	var wrap func(tun.Device) tun.Device
	if command == "packet-check" {
		wrap = func(base tun.Device) tun.Device {
			observer = &packetTUN{Device: base}
			return observer
		}
	}
	peer, err := makePeer(cfg, key, target, wrap)
	if err != nil {
		return errors.New("创建直接对端失败")
	}
	if command == "packet-check" {
		report := probePackets(context.Background(), peer, observer, *runID, requestBudget)
		peer.dev.Close()
		if err := writeResult(*resultPath, report); err != nil {
			return err
		}
		if !report.Passed {
			return errors.New("分片或 ICMP 校验失败，详见脱敏结果")
		}
		return nil
	}
	report := probe(context.Background(), peer, *runID, probeBudgets{request: requestBudget, transfer: transferBudget})
	peer.dev.Close()
	if err := writeResult(*resultPath, report); err != nil {
		return err
	}
	if !report.Passed {
		return errors.New("流量校验失败，详见脱敏结果")
	}
	return nil
}

func writeResult(path string, report any) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("创建结果文件失败")
	}
	writeErr := json.NewEncoder(file).Encode(report)
	closeErr := file.Close()
	if errors.Join(writeErr, closeErr) != nil {
		return errors.New("保存结果失败")
	}
	return nil
}

func validRunID(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, c := range value {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

func prepare(cfg *config.Config, out string) error {
	if cfg.DeviceID == "" || cfg.WireGuard.PrivateKey == "" {
		return errors.New("请先完成原测试实例的身份初始化")
	}
	key, err := wg.GenerateKey()
	if err != nil {
		return errors.New("生成测试密钥失败")
	}
	pub, err := key.PublicKey()
	if err != nil {
		return errors.New("派生测试公钥失败")
	}
	// 使用新回环端口，避免与仍处于 idle 的原测试实例或 mihomo 对端互相覆盖。
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return errors.New("选择测试端口失败")
	}
	port := socket.LocalAddr().(*net.UDPAddr).Port
	if err := socket.Close(); err != nil {
		return errors.New("释放端口探测失败")
	}
	copyConfig := *cfg
	copyConfig.WireGuard.ListenPort = port
	copyConfig.WireGuard.PeerPublicKey = pub.String()
	body, err := yaml.Marshal(&copyConfig)
	if err != nil || len(body) > 256*1024 {
		return errors.New("编码测试配置失败")
	}
	// 目录必须是新的；原配置不写回。端口若被抢占，正常启动失败，不自动重试。
	if err := os.Mkdir(out, 0700); err != nil {
		return errors.New("创建私有目录失败或目录已存在")
	}
	if err := os.WriteFile(filepath.Join(out, "config.yaml"), body, 0600); err != nil {
		return errors.New("写入独立测试配置失败")
	}
	if err := os.WriteFile(filepath.Join(out, "peer.key"), []byte(key.String()+"\n"), 0600); err != nil {
		return errors.New("写入私有对端密钥失败")
	}
	return nil
}

func readKey(path string) (wg.Key, error) {
	f, err := openKey(path)
	if err != nil {
		return wg.Key{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64 {
		return wg.Key{}, errors.New("无效密钥文件")
	}
	body, err := io.ReadAll(io.LimitReader(f, 65))
	if err != nil || len(body) > 64 {
		return wg.Key{}, errors.New("读取密钥失败")
	}
	return wg.ParseKey(strings.TrimSpace(string(body)))
}

type directPeer struct {
	dev    *device.Device
	net    *netstack.Net
	target netip.Addr
}

// 包装仅用于边界测试观测实际 IP 包；其他入口保持既有 TUN 与网络栈。
func makePeer(cfg *config.Config, key wg.Key, target netip.Addr, wrap func(tun.Device) tun.Device) (*directPeer, error) {
	serverKey, err := wg.ParseKey(cfg.WireGuard.PrivateKey)
	if err != nil {
		return nil, err
	}
	serverPub, err := serverKey.PublicKey()
	if err != nil {
		return nil, err
	}
	address, err := netip.ParseAddr(cfg.WireGuard.PeerAddress)
	if err != nil || !address.Is4() {
		return nil, errors.New("无效对端地址")
	}
	netTun, stack, err := netstack.CreateNetTUN([]netip.Addr{address}, nil, mtu)
	if err != nil {
		return nil, err
	}
	// 上游日志可能带端点地址；本测试只输出自己生成的固定类别和数值。
	if wrap != nil {
		netTun = wrap(netTun)
	}
	dev := device.NewDevice(netTun, conn.NewDefaultBind(), &device.Logger{
		Verbosef: func(string, ...any) {}, Errorf: func(string, ...any) {},
	})
	uapi := fmt.Sprintf("private_key=%s\nlisten_port=0\nreplace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=%s/32\n",
		hex.EncodeToString(key[:]), hex.EncodeToString(serverPub[:]), cfg.WireGuard.ListenPort, target.String())
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}
	return &directPeer{dev: dev, net: stack, target: target}, nil
}

type checkResult struct {
	Name        string `json:"name"`
	Passed      bool   `json:"passed"`
	BudgetMS    int64  `json:"timeout_ms"`
	ElapsedMS   int64  `json:"elapsed_ms"`
	DialMS      int64  `json:"dial_ms,omitempty"`
	FirstByteMS int64  `json:"first_byte_ms,omitempty"`
	HTTPStatus  int    `json:"http_status,omitempty"`
	Bytes       int64  `json:"bytes"`
	Error       string `json:"error_category,omitempty"`
}

type trafficReport struct {
	RunID         string        `json:"run_id"`
	Passed        bool          `json:"passed"`
	MTU           int           `json:"mtu"`
	BudgetMS      int64         `json:"request_timeout_ms"`
	TransferMS    int64         `json:"transfer_timeout_ms"`
	HandshakeSeen bool          `json:"wireguard_handshake_seen"`
	Checks        []checkResult `json:"checks"`
}

type proxyUploadReport struct {
	RunID  string      `json:"run_id"`
	Passed bool        `json:"passed"`
	Check  checkResult `json:"check"`
}

func localProxyURL(value string) (*url.URL, error) {
	if len(value) > 256 {
		return nil, errors.New("代理入口超过长度上限")
	}
	proxy, err := url.Parse(value)
	if err != nil || proxy.Scheme != "http" || proxy.User != nil || proxy.Path != "" || proxy.RawQuery != "" || proxy.Fragment != "" {
		return nil, errors.New("代理入口无效")
	}
	address, err := netip.ParseAddrPort(proxy.Host)
	if err != nil || !address.Addr().Is4() || !address.Addr().IsLoopback() || address.Port() == 0 {
		return nil, errors.New("代理入口不是 IPv4 回环地址")
	}
	return proxy, nil
}

func probeProxyUpload(parent context.Context, proxy *url.URL, target netip.Addr, runID string, budget time.Duration) checkResult {
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true, MaxConnsPerHost: 1, ExpectContinueTimeout: 350 * time.Millisecond}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != proxy.Host {
			return nil, errors.New("拒绝代理入口以外的连接")
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	headers := http.Header{"Content-Type": {"application/octet-stream"}, "Expect": {"100-continue"}, "User-Agent": {""}}
	return measureHTTP(parent, transport, headers, httpTarget(target).String(), runID, budget, "upload-1MiB-go-http-proxy", "POST", "/echo", uploadHash, uploadSize)
}

type measurement struct {
	mu          sync.Mutex
	started     time.Time
	dialMS      int64
	firstByteMS int64
}

func (m *measurement) update(dial bool, elapsed int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if dial {
		m.dialMS = elapsed
	} else {
		m.firstByteMS = elapsed
	}
}

type probeBudgets struct {
	request, transfer time.Duration
}

type httpCheck struct {
	name, method, path, digest string
	size                       int
	budget                     time.Duration
}

func httpChecks(budgets probeBudgets) []httpCheck {
	return []httpCheck{
		{"health", "GET", "/health", "", len("njuvpn-release-test\n"), budgets.request},
		{"download-8MiB", "GET", "/slow-blob", downloadHash, downloadSize, budgets.transfer},
		{"upload-1MiB", "POST", "/echo", uploadHash, uploadSize, budgets.transfer},
	}
}

func probe(ctx context.Context, peer *directPeer, runID string, budgets probeBudgets) (report trafficReport) {
	report = trafficReport{RunID: runID, MTU: mtu, BudgetMS: budgets.request.Milliseconds(), TransferMS: budgets.transfer.Milliseconds()}
	defer func() {
		report.HandshakeSeen = handshakeSeen(peer)
		report.Passed = report.Passed && report.HandshakeSeen
	}()
	for _, test := range httpChecks(budgets) {
		result := probeHTTP(ctx, peer, runID, test.budget, test.name, test.method, test.path, test.digest, test.size)
		report.Checks = append(report.Checks, result)
		if !result.Passed {
			return report
		}
	}
	for _, size := range []int{32, 1372} {
		result := probeUDP(ctx, peer, budgets.request, size)
		report.Checks = append(report.Checks, result)
		if !result.Passed {
			return report
		}
	}
	report.Passed = true
	return report
}

func handshakeSeen(peer *directPeer) bool {
	text, err := peer.dev.IpcGet()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(text, "\n") {
		if value, ok := strings.CutPrefix(line, "last_handshake_time_sec="); ok && value != "0" {
			return true
		}
	}
	return false
}

func probeHTTP(parent context.Context, peer *directPeer, runID string, budget time.Duration, name, method, path, expectedHash string, size int) (result checkResult) {
	transport := &http.Transport{DisableKeepAlives: true, MaxConnsPerHost: 1}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != httpTarget(peer.target).String() {
			return nil, errors.New("拒绝测试目标以外的连接")
		}
		return peer.net.DialContextTCPAddrPort(ctx, httpTarget(peer.target))
	}
	return measureHTTP(parent, transport, nil, httpTarget(peer.target).String(), runID, budget, name, method, path, expectedHash, size)
}

// transport 的独占所有权转入本次测量：修改拨号计时包装，并在退出时回收连接。
func measureHTTP(parent context.Context, transport *http.Transport, headers http.Header, targetAddress, runID string, budget time.Duration, name, method, path, expectedHash string, size int) (result checkResult) {
	clock := &measurement{started: time.Now(), dialMS: -1, firstByteMS: -1}
	result.Name = name
	result.BudgetMS = budget.Milliseconds()
	defer func() {
		result.ElapsedMS = time.Since(clock.started).Milliseconds()
		clock.mu.Lock()
		result.DialMS, result.FirstByteMS = clock.dialMS, clock.firstByteMS
		clock.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	dial := transport.DialContext
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		started := time.Now()
		connection, err := dial(ctx, network, address)
		clock.update(true, time.Since(started).Milliseconds())
		return connection, err
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var body io.Reader
	if method == "POST" {
		body = bytes.NewReader(payload(size, 256))
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://"+targetAddress+path, body)
	if err != nil {
		result.Error = "request"
		return result
	}
	request.Header.Set("X-Njuvpn-Test-Id", runID)
	for name, values := range headers {
		request.Header[name] = append([]string(nil), values...)
	}
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{
		GotFirstResponseByte: func() { clock.update(false, time.Since(clock.started).Milliseconds()) },
	}))
	response, err := client.Do(request)
	if err != nil {
		result.Error = classify(err)
		return result
	}
	defer response.Body.Close()
	result.HTTPStatus = response.StatusCode
	if response.StatusCode != http.StatusOK || response.ContentLength != int64(size) {
		result.Error = "http-status-or-length"
		return result
	}
	hash := sha256.New()
	result.Bytes, err = io.Copy(hash, io.LimitReader(response.Body, int64(size)+1))
	if err != nil {
		result.Error = classify(err)
		return result
	}
	if expectedHash == "" {
		healthHash := sha256.Sum256([]byte("njuvpn-release-test\n"))
		expectedHash = hex.EncodeToString(healthHash[:])
	}
	if result.Bytes != int64(size) || hex.EncodeToString(hash.Sum(nil)) != expectedHash {
		result.Error = "content"
		return result
	}
	result.Passed = true
	return result
}

func payload(size, modulo int) []byte {
	body := make([]byte, size)
	for i := range body {
		body[i] = byte(i % modulo)
	}
	return body
}

func probeUDP(parent context.Context, peer *directPeer, budget time.Duration, size int) (result checkResult) {
	started := time.Now()
	result.Name = fmt.Sprintf("udp-%d", size)
	result.BudgetMS = budget.Milliseconds()
	defer func() { result.ElapsedMS = time.Since(started).Milliseconds() }()
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	connection, err := peer.net.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(peer.target, udpPort))
	if err != nil {
		result.Error = classify(err)
		return result
	}
	closed := make(chan struct{})
	stopCancel := context.AfterFunc(ctx, func() {
		connection.Close()
		close(closed)
	})
	defer func() {
		if !stopCancel() {
			<-closed
		}
		connection.Close()
	}()
	deadline, _ := ctx.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		result.Error = classify(err)
		return result
	}
	body := payload(size, 251)
	if _, err := connection.Write(body); err != nil {
		result.Error = classify(err)
		return result
	}
	received := make([]byte, size+1)
	n, err := connection.Read(received)
	result.Bytes = int64(n)
	if err != nil {
		result.Error = classify(err)
		return result
	}
	if !bytes.Equal(body, received[:n]) {
		result.Error = "content"
		return result
	}
	result.Passed = true
	return result
}

func classify(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "unexpected-eof"
	case errors.Is(err, io.EOF):
		return "eof"
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return "timeout"
	}
	return "network-or-io"
}
