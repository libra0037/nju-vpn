package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"time"

	"github.com/libra0037/nju-vpn/internal/config"
	"github.com/libra0037/nju-vpn/internal/ipc"
	wg "github.com/libra0037/nju-vpn/internal/wireguard"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	halfClosePort = 18082
	echoTCPPort   = 18083
	// 局部重建会清空服务端 WireGuard 密钥状态；旧对端的 TCP 首次实测超过
	// 30 秒。恢复单独限为 60 秒，保留计时，不给普通请求或传输增加重试。
	endpointRecoveryBudget = 60 * time.Second
)

// 配置副本和直接对端属于本工具，服务进程由调用脚本启动、登录并关闭。
// 只改测试端点参数；账号、设备身份、节点 pin 和出站方式来自用户的当前配置。
func runCampus(command string, args []string) error {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", "", "当前私有配置")
	out := flags.String("out", "", "新的私有目录")
	keyPath := flags.String("key", "", "测试对端密钥")
	resultPath := flags.String("result", "", "新的结果文件")
	runID := flags.String("run-id", "", "关联标识")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *path == "" {
		return errors.New("校园测试参数无效")
	}
	cfg, err := config.LoadForClient(*path)
	if err != nil {
		return errors.New("校园测试配置无效")
	}
	switch command {
	case "campus-prepare":
		if *out == "" || *keyPath != "" || *resultPath != "" || *runID != "" {
			return errors.New("校园配置准备参数无效")
		}
		prior, err := ipcCall(context.Background(), cfg.SourcePath(), ipc.CmdState, nil, time.Second)
		if err == nil && (prior.Code != ipc.CodeOK || prior.Message != "idle") {
			return errors.New("请先断开原实例，校园账号不同时登录两个测试实例")
		}
		if err != nil && !errors.Is(err, ipc.ErrNotRunning) {
			return errors.New("无法核验原实例状态")
		}
		return prepareCampus(cfg, *out)
	case "campus-run":
		if *out != "" || *keyPath == "" || *resultPath == "" || !validRunID(*runID) {
			return errors.New("校园流量参数无效")
		}
		if !cfg.WireGuard.Enabled || !cfg.SOCKS5.Enabled || cfg.WireGuard.MTU != mtu || cfg.WireGuard.ListenHost != "loopback" || cfg.SOCKS5.ListenHost != "loopback" {
			return errors.New("校园测试要求已准备的双端回环配置")
		}
		key, err := readKey(*keyPath)
		if err != nil {
			return errors.New("校园对端密钥无效")
		}
		pub, err := key.PublicKey()
		if err != nil || pub.String() != cfg.WireGuard.PeerPublicKey {
			return errors.New("校园对端密钥与配置不匹配")
		}
		target, err := targetFromEnvironment()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		report := probeCampus(ctx, cfg, key, target, *runID)
		if err := writeResult(*resultPath, report); err != nil {
			return err
		}
		if !report.Passed {
			return errors.New("校园测试失败，详见结果文件")
		}
		return nil
	case "campus-close":
		if *out != "" || *keyPath != "" || *resultPath == "" || *runID != "" {
			return errors.New("校园收尾参数无效")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()
		stopped := closeCampus(ctx, cfg.SourcePath())
		if err := writeResult(*resultPath, struct {
			ServiceStopped bool   `json:"service_stopped"`
			InstanceTag    string `json:"instance_tag"`
		}{stopped, ipc.InstanceTag(cfg.SourcePath())}); err != nil {
			return err
		}
		if !stopped {
			return errors.New("校园测试服务未完整关闭")
		}
		return nil
	default:
		return errors.New("校园测试命令无效")
	}
}

func prepareCampus(cfg *config.Config, out string) error {
	copyConfig := *cfg
	copyConfig.WireGuard.Enabled = true
	copyConfig.WireGuard.MTU = mtu
	copyConfig.WireGuard.ListenHost = "loopback"
	// SOCKS-only 的原实例没有 WireGuard 私钥，新增的密钥只写入副本。
	if copyConfig.WireGuard.PrivateKey == "" {
		key, err := wg.GenerateKey()
		if err != nil {
			return errors.New("生成测试服务密钥失败")
		}
		copyConfig.WireGuard.PrivateKey = key.String()
	}
	socket, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return errors.New("选择测试 SOCKS 端口失败")
	}
	port := socket.Addr().(*net.TCPAddr).Port
	if err := socket.Close(); err != nil {
		return errors.New("释放测试 SOCKS 端口失败")
	}
	copyConfig.SOCKS5.Enabled = true
	copyConfig.SOCKS5.ListenHost = "loopback"
	copyConfig.SOCKS5.ListenPort = port
	copyConfig.SOCKS5.MaxConnections = 8
	copyConfig.SOCKS5.MaxDials = 4
	return prepare(&copyConfig, out)
}

func closeCampus(ctx context.Context, path string) bool {
	response, err := ipcCall(ctx, path, ipc.CmdStop, nil, 20*time.Second)
	if errors.Is(err, ipc.ErrNotRunning) {
		return true
	}
	stopOK := err == nil && response.Code == ipc.CodeOK
	// stop 失败时仍尝试回收自己启动的进程，不将失败吞成 PASS。
	response, err = ipcCall(ctx, path, ipc.CmdShutdown, nil, 5*time.Second)
	shutdownOK := errors.Is(err, ipc.ErrNotRunning) || err == nil && response.Code == ipc.CodeOK
	stopped := shutdownOK && waitStopped(ctx, path, 10*time.Second)
	return stopOK && stopped
}

type campusStatus struct {
	State        string    `json:"state"`
	SessionReady bool      `json:"session_ready"`
	Since        time.Time `json:"since"`
	Identity     struct {
		PID int `json:"pid"`
	} `json:"identity"`
	WireGuard struct {
		Enabled, Listening bool
	} `json:"wireguard"`
	SOCKS5 struct {
		Enabled, Listening bool
	} `json:"socks5"`
}

func readCampusStatus(ctx context.Context, path string) (campusStatus, error) {
	response, err := ipcCall(ctx, path, ipc.CmdStatus, []string{"json"}, 2*time.Second)
	var status campusStatus
	if err != nil || response.Code != ipc.CodeOK || json.Unmarshal([]byte(response.Message), &status) != nil {
		return status, errFaultCheck
	}
	return status, nil
}

func sameCampusSession(before, after campusStatus, wireguard, socks bool) bool {
	return after.State == "up" && after.SessionReady && before.Identity.PID > 0 && before.Identity.PID == after.Identity.PID && !before.Since.IsZero() && before.Since.Equal(after.Since) &&
		after.WireGuard.Enabled == wireguard && after.WireGuard.Listening == wireguard && after.SOCKS5.Enabled == socks && after.SOCKS5.Listening == socks
}

func campusResources(ctx context.Context, path string) (ipc.Resources, [32]byte, error) {
	response, err := ipcCall(ctx, path, ipc.CmdResources, nil, 3*time.Second)
	var resources ipc.Resources
	if err != nil || response.Code != ipc.CodeOK || json.Unmarshal([]byte(response.Message), &resources) != nil || resources.Validate() != nil || len(resources.IP)+len(resources.TCPDomains) == 0 {
		return resources, [32]byte{}, errFaultCheck
	}
	return resources, sha256.Sum256([]byte(response.Message)), nil
}

type campusReport struct {
	RunID           string        `json:"run_id"`
	Passed          bool          `json:"passed"`
	IPRules         int           `json:"ip_rules"`
	TCPDomains      int           `json:"tcp_domains"`
	ResourcesSHA256 string        `json:"resources_sha256"`
	SOCKSAuth       bool          `json:"socks_auth"`
	Checks          []checkResult `json:"checks"`
	WireGuard       trafficReport `json:"wireguard"`
	Packets         packetReport  `json:"packets"`
	SOCKS           socksReport   `json:"socks5"`
}

func probeCampus(ctx context.Context, cfg *config.Config, key wg.Key, target netip.Addr, runID string) (report campusReport) {
	report.RunID, report.SOCKSAuth = runID, cfg.SOCKS5.Username != ""
	check := func(name string, budget time.Duration, action func(context.Context) error) bool {
		_, _ = io.WriteString(os.Stdout, "开始校园测试: "+name+"\n")
		started := time.Now()
		step, cancel := context.WithTimeout(ctx, budget)
		defer cancel()
		err := action(step)
		if err != nil && step.Err() != nil {
			err = step.Err()
		}
		r := checkResult{Name: name, Passed: err == nil, BudgetMS: budget.Milliseconds(), ElapsedMS: time.Since(started).Milliseconds()}
		if err != nil {
			r.Error = classify(err)
		}
		report.Checks = append(report.Checks, r)
		// 阶段提示不包含配置或业务地址，便于用户看到大传输仍在执行。
		_, _ = io.WriteString(os.Stdout, "校园测试阶段: "+name+"\n")
		return r.Passed
	}
	path := cfg.SourcePath()
	var before campusStatus
	if !check("both-endpoints-ready", 3*time.Second, func(step context.Context) error {
		var err error
		before, err = readCampusStatus(step, path)
		if err != nil || !sameCampusSession(before, before, true, true) {
			return errFaultCheck
		}
		return nil
	}) {
		return report
	}
	var resources ipc.Resources
	var resourceHash [32]byte
	if !check("resources-complete", 3*time.Second, func(step context.Context) error {
		var err error
		resources, resourceHash, err = campusResources(step, path)
		return err
	}) {
		return report
	}
	report.IPRules, report.TCPDomains = len(resources.IP), len(resources.TCPDomains)
	report.ResourcesSHA256 = hex.EncodeToString(resourceHash[:])
	observer := &packetTUN{}
	peer, err := makePeer(cfg, key, target, func(base tun.Device) tun.Device { observer.Device = base; return observer })
	if !check("direct-peer-created", 3*time.Second, func(context.Context) error { return err }) {
		return report
	}
	defer peer.dev.Close()
	budgets := probeBudgets{request: requestBudget, transfer: transferBudget}
	if !check("wireguard-fixed-transfers", 4*time.Minute, func(step context.Context) error {
		report.WireGuard = probe(step, peer, runID, budgets)
		if !report.WireGuard.Passed {
			return errFaultCheck
		}
		return nil
	}) {
		return report
	}
	if !check("wireguard-mtu-fragments", 2*time.Minute, func(step context.Context) error {
		report.Packets = probePackets(step, peer, observer, runID, requestBudget)
		if !report.Packets.Passed {
			return errFaultCheck
		}
		return nil
	}) {
		return report
	}
	proxy := socksURL(cfg)
	if !check("socks-fixed-transfers", 4*time.Minute, func(step context.Context) error {
		report.SOCKS = probeSOCKS(step, proxy, httpTarget(target).String(), "ipv4", runID, budgets)
		if !report.SOCKS.Passed {
			return errFaultCheck
		}
		return nil
	}) {
		return report
	}
	halfClose := probeSOCKSHalfClose(ctx, cfg, netip.AddrPortFrom(target, halfClosePort), transferBudget)
	report.Checks = append(report.Checks, halfClose)
	if !halfClose.Passed {
		return report
	}
	if !check("socks-domain-tls", requestBudget, func(step context.Context) error {
		transport := socksTransport(proxy)
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		request, err := http.NewRequestWithContext(step, "HEAD", "https://www.nature.com/", nil)
		if err != nil {
			return err
		}
		response, err := client.Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 || response.StatusCode < 200 || response.StatusCode >= 500 {
			return errFaultCheck
		}
		return nil
	}) {
		return report
	}
	// 先测试 SOCKS 停止，避免把后面的 WireGuard 密钥重建混入这项判据。
	connection, err := dialCampusSOCKS(ctx, cfg, netip.AddrPortFrom(target, echoTCPPort))
	if !check("socks-held-stream", requestBudget, func(context.Context) error { return err }) {
		return report
	}
	defer connection.Close()
	endpoint := func(step context.Context, command, name string, wireguard, socks bool) error {
		response, err := ipcCall(step, path, command, []string{name}, 5*time.Second)
		if err != nil || response.Code != ipc.CodeOK {
			return errFaultCheck
		}
		for step.Err() == nil {
			status, err := readCampusStatus(step, path)
			if err == nil && sameCampusSession(before, status, wireguard, socks) {
				return nil
			}
			if pause(step, 50*time.Millisecond) != nil {
				break
			}
		}
		return step.Err()
	}
	if !check("stop-socks-only", 8*time.Second, func(step context.Context) error { return endpoint(step, ipc.CmdEndpointStop, "socks5", true, false) }) ||
		!check("socks-active-stream-closed", 3*time.Second, func(step context.Context) error {
			deadline, _ := step.Deadline()
			if err := connection.SetReadDeadline(deadline); err != nil {
				return err
			}
			var one [1]byte
			_, err := connection.Read(one[:])
			var timeout net.Error
			if err == nil || errors.As(err, &timeout) && timeout.Timeout() {
				return errFaultCheck
			}
			return nil
		}) ||
		!check("wireguard-traffic-with-socks-disabled", requestBudget, func(step context.Context) error {
			if !probeHTTP(step, peer, runID, requestBudget, "health", "GET", "/health", "", 20).Passed || !probeUDP(step, peer, requestBudget, 32).Passed {
				return errFaultCheck
			}
			return nil
		}) ||
		!check("start-socks-only", 8*time.Second, func(step context.Context) error { return endpoint(step, ipc.CmdEndpointStart, "socks5", true, true) }) ||
		!check("socks-traffic-after-restart", requestBudget, func(step context.Context) error {
			r := measureHTTP(step, socksTransport(proxy), nil, httpTarget(target).String(), runID, requestBudget, "health", "GET", "/health", "", 20)
			if !r.Passed {
				return errFaultCheck
			}
			return nil
		}) {
		return report
	}
	// 另一条 L4 流从创建起一直跨越 WireGuard 停止、重启，不能靠重建它掩盖中断。
	held, err := dialCampusSOCKS(ctx, cfg, netip.AddrPortFrom(target, echoTCPPort))
	if !check("socks-stream-for-wireguard-restart", requestBudget, func(context.Context) error { return err }) {
		return report
	}
	defer held.Close()
	if !check("socks-stream-before-wireguard-stop", requestBudget, func(step context.Context) error { return campusEcho(step, held) }) ||
		!check("stop-wireguard-only", 8*time.Second, func(step context.Context) error { return endpoint(step, ipc.CmdEndpointStop, "wireguard", false, true) }) ||
		!check("socks-stream-with-wireguard-disabled", requestBudget, func(step context.Context) error { return campusEcho(step, held) }) ||
		!check("start-wireguard-only", 8*time.Second, func(step context.Context) error { return endpoint(step, ipc.CmdEndpointStart, "wireguard", true, true) }) ||
		!check("socks-stream-after-wireguard-restart", requestBudget, func(step context.Context) error { return campusEcho(step, held) }) {
		return report
	}
	_, _ = io.WriteString(os.Stdout, "开始校园测试: wireguard-tcp-after-endpoint-restart\n")
	recovery := probeHTTP(ctx, peer, runID, endpointRecoveryBudget, "wireguard-tcp-after-endpoint-restart", "GET", "/health", "", 20)
	report.Checks = append(report.Checks, recovery)
	if !recovery.Passed {
		return report
	}
	if !check("same-login-and-resources", 5*time.Second, func(step context.Context) error {
		status, err := readCampusStatus(step, path)
		_, after, resourceErr := campusResources(step, path)
		if err != nil || resourceErr != nil || after != resourceHash || !sameCampusSession(before, status, true, true) {
			return errFaultCheck
		}
		return nil
	}) ||
		!check("heartbeat-idle-50s", time.Minute, func(step context.Context) error {
			if err := pause(step, 50*time.Second); err != nil {
				return err
			}
			status, err := readCampusStatus(step, path)
			if err != nil || !sameCampusSession(before, status, true, true) {
				return errFaultCheck
			}
			return nil
		}) {
		return report
	}
	report.Passed = true
	return report
}

// 回收取消回调后才交还所有权，避免退出时仍有回调访问连接。
type campusConn struct {
	*net.TCPConn
	stop func() bool
	done chan struct{}
}

func (c *campusConn) Close() error {
	err := c.TCPConn.Close()
	if !c.stop() {
		<-c.done
	}
	return err
}

func dialCampusSOCKS(ctx context.Context, cfg *config.Config, target netip.AddrPort) (_ *campusConn, resultErr error) {
	address := socksURL(cfg).Host
	base, err := (&net.Dialer{}).DialContext(ctx, "tcp4", address)
	if err != nil {
		return nil, err
	}
	c := &campusConn{TCPConn: base.(*net.TCPConn), done: make(chan struct{})}
	c.stop = context.AfterFunc(ctx, func() { c.TCPConn.Close(); close(c.done) })
	defer func() {
		if resultErr != nil {
			c.Close()
		}
	}()
	// 握手有独立期限；后续读取由持有连接的检查设置自己的期限。
	deadline := time.Now().Add(requestBudget)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	if err := c.SetDeadline(deadline); err != nil {
		return nil, err
	}
	method := byte(0)
	if cfg.SOCKS5.Username != "" {
		method = 2
	}
	if _, err := c.Write([]byte{5, 1, method}); err != nil {
		return nil, err
	}
	var reply [2]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		return nil, err
	}
	if reply != [2]byte{5, method} {
		return nil, errFaultCheck
	}
	if method == 2 {
		body := []byte{1, byte(len(cfg.SOCKS5.Username))}
		body = append(body, cfg.SOCKS5.Username...)
		body = append(body, byte(len(cfg.SOCKS5.Password)))
		body = append(body, cfg.SOCKS5.Password...)
		if _, err := c.Write(body); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(c, reply[:]); err != nil {
			return nil, err
		}
		if reply != [2]byte{1, 0} {
			return nil, errFaultCheck
		}
	}
	ip := target.Addr().As4()
	request := []byte{5, 1, 0, 1, ip[0], ip[1], ip[2], ip[3], byte(target.Port() >> 8), byte(target.Port())}
	if _, err := c.Write(request); err != nil {
		return nil, err
	}
	var header [4]byte
	if _, err := io.ReadFull(c, header[:]); err != nil {
		return nil, err
	}
	if header[0] != 5 || header[1] != 0 || header[2] != 0 {
		return nil, errFaultCheck
	}
	var size int
	switch header[3] {
	case 1:
		size = 4
	case 4:
		size = 16
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(c, length[:]); err != nil || length[0] == 0 {
			return nil, errFaultCheck
		}
		size = int(length[0])
	default:
		return nil, errFaultCheck
	}
	if _, err := io.CopyN(io.Discard, c, int64(size+2)); err != nil {
		return nil, err
	}
	if err := c.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return c, nil
}

func campusEcho(ctx context.Context, c *campusConn) error {
	deadline, _ := ctx.Deadline()
	if err := c.SetDeadline(deadline); err != nil {
		return err
	}
	// 固定样例而非从接收数据派生期望值。
	want := []byte("njuvpn-held-campus-stream\n")
	if _, err := c.Write(want); err != nil {
		return err
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	if !bytes.Equal(want, got) {
		return errFaultCheck
	}
	return nil
}

func probeSOCKSHalfClose(parent context.Context, cfg *config.Config, target netip.AddrPort, budget time.Duration) (result checkResult) {
	started := time.Now()
	result.Name, result.BudgetMS = "socks-half-close-1MiB", budget.Milliseconds()
	defer func() { result.ElapsedMS = time.Since(started).Milliseconds() }()
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	c, err := dialCampusSOCKS(ctx, cfg, target)
	if err != nil {
		result.Error = classify(err)
		return result
	}
	defer c.Close()
	deadline, _ := ctx.Deadline()
	if err = c.SetDeadline(deadline); err == nil {
		_, err = io.Copy(c, bytes.NewReader(payload(uploadSize, 256)))
	}
	if err == nil {
		err = c.CloseWrite()
	}
	if err != nil {
		result.Error = classify(err)
		return result
	}
	hash := sha256.New()
	result.Bytes, err = io.Copy(hash, io.LimitReader(c, uploadSize+1))
	if err != nil {
		result.Error = classify(err)
		return result
	}
	result.Passed = result.Bytes == uploadSize && hex.EncodeToString(hash.Sum(nil)) == uploadHash
	if !result.Passed {
		result.Error = "content"
	}
	return result
}
