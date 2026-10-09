package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/libra0037/nju-vpn/internal/config"
	"github.com/libra0037/nju-vpn/internal/dial"
	"github.com/libra0037/nju-vpn/internal/ipc"
)

type resilienceReport struct {
	RunID                   string        `json:"run_id"`
	Passed                  bool          `json:"passed"`
	Checks                  []checkResult `json:"checks"`
	OriginalConfigUnchanged bool          `json:"original_config_unchanged"`
	PrivateConfigUnchanged  bool          `json:"private_config_unchanged"`
	ServiceStopped          bool          `json:"service_stopped"`
	ProxyStopped            bool          `json:"proxy_stopped"`
	ProxyAccepted           int           `json:"proxy_accepted_connections"`
	ProxyRefused            int           `json:"proxy_refused_connections"`
	ProxyDiscarded          int64         `json:"proxy_discarded_bytes"`
}

func runResilience(args []string) (resultErr error) {
	flags := flag.NewFlagSet("resilience", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	sourcePath := flags.String("config", "", "原测试配置")
	binaryPath := flags.String("binary", "", "候选 njuvpn 程序")
	out := flags.String("out", "", "新的私有目录")
	resultPath := flags.String("result", "", "新的公开结果文件")
	runID := flags.String("run-id", "", "关联标识")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *sourcePath == "" || *binaryPath == "" || *out == "" || *resultPath == "" || !validRunID(*runID) {
		return errors.New("断线测试参数无效")
	}
	target, err := targetFromEnvironment()
	if err != nil {
		return err
	}
	cfg, err := config.LoadForClient(*sourcePath)
	if err != nil || cfg.Password == "" || !cfg.WireGuard.Enabled || cfg.WireGuard.MTU != mtu {
		return errors.New("断线测试要求有效配置、已填写 password、MTU 1400")
	}
	sourceBody, err := os.ReadFile(cfg.SourcePath())
	if err != nil {
		return errors.New("读取原配置失败")
	}
	sourceHash := sha256.Sum256(sourceBody)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	prior, err := ipcCall(ctx, cfg.SourcePath(), ipc.CmdState, nil, time.Second)
	if err == nil && (prior.Code != ipc.CodeOK || prior.Message != "idle") {
		return errors.New("原实例仍有活动会话")
	}
	if err != nil && !errors.Is(err, ipc.ErrNotRunning) {
		return errors.New("无法确认原实例状态")
	}
	dialer, err := dial.New(cfg.Proxy)
	if err != nil {
		return errors.New("原出站配置无效")
	}
	proxy, err := newFaultProxy(ctx, dialer)
	if err != nil {
		return errors.New("启动受控回环代理失败")
	}
	defer proxy.close()
	copyConfig := *cfg
	copyConfig.Proxy = proxy.address()
	if err := prepare(&copyConfig, *out); err != nil {
		return err
	}
	testPath := filepath.Join(*out, "config.yaml")
	privateBody, err := os.ReadFile(testPath)
	if err != nil {
		return errors.New("读取独立配置失败")
	}
	privateHash := sha256.Sum256(privateBody)
	logFile, err := os.OpenFile(filepath.Join(*out, "runner.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("创建私有日志失败")
	}
	defer logFile.Close()
	log := &cappedLog{writer: logFile, remaining: 1024 * 1024}
	report := resilienceReport{RunID: *runID}
	owned := false
	defer func() {
		// 先恢复出站再登出。只关闭本工具创建的配置实例。
		proxy.restore()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		if owned {
			_, _ = ipcCall(cleanupCtx, testPath, ipc.CmdStop, nil, 8*time.Second)
			response, err := ipcCall(cleanupCtx, testPath, ipc.CmdShutdown, nil, 5*time.Second)
			if err == nil && response.Code == ipc.CodeOK || errors.Is(err, ipc.ErrNotRunning) {
				report.ServiceStopped = waitStopped(cleanupCtx, testPath, 3*time.Second)
			}
		}
		proxy.close()
		report.ProxyStopped = true
		after, err := os.ReadFile(cfg.SourcePath())
		report.OriginalConfigUnchanged = err == nil && sha256.Sum256(after) == sourceHash
		after, err = os.ReadFile(testPath)
		report.PrivateConfigUnchanged = err == nil && sha256.Sum256(after) == privateHash
		report.ProxyAccepted, report.ProxyRefused, report.ProxyDiscarded = proxy.counts()
		report.Passed = resultErr == nil && report.ServiceStopped && report.ProxyStopped && report.OriginalConfigUnchanged && report.PrivateConfigUnchanged
		if err := writeResult(*resultPath, report); err != nil {
			resultErr = err
		} else if !report.Passed && resultErr == nil {
			resultErr = errors.New("断线测试收尾或配置不变检查失败")
		}
	}()
	check := func(name string, budget time.Duration, action func(context.Context) error) error {
		started := time.Now()
		step, stop := context.WithTimeout(ctx, budget)
		defer stop()
		err := action(step)
		r := checkResult{Name: name, Passed: err == nil, BudgetMS: budget.Milliseconds(), ElapsedMS: time.Since(started).Milliseconds()}
		if err != nil {
			r.Error = "fault-or-recovery"
		}
		report.Checks = append(report.Checks, r)
		return err
	}
	owned = true
	if err := check("restart-independent-instance", 20*time.Second, func(ctx context.Context) error {
		commandCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		command := exec.CommandContext(commandCtx, *binaryPath, "restart", "-config", testPath)
		command.Stdout, command.Stderr = log, log
		if command.Run() != nil {
			return errors.New("独立服务启动失败")
		}
		return nil
	}); err != nil {
		return err
	}
	start := func(ctx context.Context) error {
		response, err := ipcCall(ctx, testPath, ipc.CmdStart, []string{"trust=0"}, 40*time.Second)
		if err != nil || response.Code != ipc.CodeOK {
			return errors.New("登录失败或需要验证码，详见私有日志")
		}
		return nil
	}
	if err := check("login-without-trust", 40*time.Second, start); err != nil {
		return err
	}
	testConfig, err := config.LoadForClient(testPath)
	if err != nil {
		return errors.New("独立测试配置无效")
	}
	key, err := readKey(filepath.Join(*out, "peer.key"))
	if err != nil {
		return errors.New("独立对端密钥无效")
	}
	peer, err := makePeer(testConfig, key, target, nil)
	if err != nil {
		return errors.New("创建故障测试对端失败")
	}
	defer func() { peer.dev.Close() }()
	health := func(ctx context.Context) error {
		result := probeHTTP(ctx, peer, *runID, requestBudget, "health", "GET", "/health", "", 20)
		if !result.Passed {
			return errFaultCheck
		}
		return nil
	}
	if err := check("baseline-wireguard-health", requestBudget, health); err != nil {
		return err
	}
	if err := check("temporary-disconnect-recovery", 40*time.Second, func(ctx context.Context) error {
		if proxy.cut(true) == 0 {
			return errFaultCheck
		}
		if !waitStatus(ctx, testPath, "up", ipc.CodeRejected, 3*time.Second) {
			return errFaultCheck
		}
		if err := pause(ctx, 2*time.Second); err != nil {
			return err
		}
		proxy.restore()
		if !waitStatus(ctx, testPath, "up", ipc.CodeOK, 10*time.Second) {
			return errFaultCheck
		}
		return health(ctx)
	}); err != nil {
		return err
	}
	if err := check("silent-peer-heartbeat-recovery", 90*time.Second, func(ctx context.Context) error {
		_, _, before := proxy.counts()
		proxy.setSilent(true)
		if !waitStatus(ctx, testPath, "up", ipc.CodeRejected, 55*time.Second) {
			return errFaultCheck
		}
		_, _, after := proxy.counts()
		if after <= before {
			return errFaultCheck
		}
		proxy.restore()
		// 静默期间丢掉的是 TLS 字节流，恢复依靠新的 TLS 连接。
		if !waitStatus(ctx, testPath, "up", ipc.CodeOK, 10*time.Second) {
			return errFaultCheck
		}
		return health(ctx)
	}); err != nil {
		return err
	}
	if err := check("reconnect-budget-exhausted", 20*time.Second, func(ctx context.Context) error {
		if proxy.cut(true) == 0 {
			return errFaultCheck
		}
		if !waitStatus(ctx, testPath, "error", ipc.CodeRejected, 15*time.Second) {
			return errFaultCheck
		}
		proxy.restore()
		before, _, _ := proxy.counts()
		if err := pause(ctx, 4*time.Second); err != nil {
			return err
		}
		after, _, _ := proxy.counts()
		if after != before || !waitStatus(ctx, testPath, "error", ipc.CodeRejected, time.Second) {
			return errFaultCheck
		}
		return nil
	}); err != nil {
		return err
	}
	if err := check("manual-start-after-budget-exhausted", 70*time.Second, func(ctx context.Context) error {
		if err := start(ctx); err != nil {
			return err
		}
		peer.dev.Close()
		fresh, err := makePeer(testConfig, key, target, nil)
		if err != nil {
			return errFaultCheck
		}
		peer = fresh
		return health(ctx)
	}); err != nil {
		return err
	}
	if err := check("stop-cancels-reconnection", 15*time.Second, func(ctx context.Context) error {
		if proxy.cut(true) == 0 || !waitStatus(ctx, testPath, "up", ipc.CodeRejected, 3*time.Second) {
			return errFaultCheck
		}
		response, err := ipcCall(ctx, testPath, ipc.CmdStop, nil, 8*time.Second)
		if err != nil || response.Code != ipc.CodeOK {
			return errFaultCheck
		}
		proxy.restore()
		before, _, _ := proxy.counts()
		if err := pause(ctx, 4*time.Second); err != nil {
			return err
		}
		after, _, _ := proxy.counts()
		if after != before || !waitStatus(ctx, testPath, "idle", ipc.CodeRejected, time.Second) {
			return errFaultCheck
		}
		result := probeHTTP(ctx, peer, *runID, time.Second, "stopped", "GET", "/health", "", 20)
		if result.Passed {
			return errFaultCheck
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

func ipcCall(parent context.Context, path, command string, args []string, budget time.Duration) (ipc.Response, error) {
	return ipc.NewClient(path).CallContext(parent, ipc.Request{Command: command, Args: args}, budget)
}

func waitStatus(parent context.Context, path, wantState string, wantCode int, budget time.Duration) bool {
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	for ctx.Err() == nil {
		state, err := ipcCall(ctx, path, ipc.CmdState, nil, time.Second)
		status, statusErr := ipcCall(ctx, path, ipc.CmdStatus, nil, time.Second)
		if err == nil && statusErr == nil && state.Code == ipc.CodeOK && state.Message == wantState && status.Code == wantCode {
			return true
		}
		if pause(ctx, 50*time.Millisecond) != nil {
			return false
		}
	}
	return false
}

func waitStopped(parent context.Context, path string, budget time.Duration) bool {
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	for ctx.Err() == nil {
		_, err := ipcCall(ctx, path, ipc.CmdState, nil, time.Second)
		if errors.Is(err, ipc.ErrNotRunning) {
			return true
		}
		if pause(ctx, 50*time.Millisecond) != nil {
			return false
		}
	}
	return false
}

func pause(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type cappedLog struct {
	mu        sync.Mutex
	writer    io.Writer
	remaining int
}

func (w *cappedLog) Write(body []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := len(body)
	limit := min(w.remaining, n)
	if limit > 0 {
		written, err := w.writer.Write(body[:limit])
		w.remaining -= written
		if err != nil {
			return written, err
		}
		if written != limit {
			return written, io.ErrShortWrite
		}
	}
	return n, nil
}
