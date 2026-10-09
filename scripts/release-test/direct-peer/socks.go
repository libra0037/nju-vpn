package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"

	"github.com/libra0037/nju-vpn/internal/config"
	"github.com/libra0037/nju-vpn/internal/domain"
)

type socksReport struct {
	RunID      string        `json:"run_id"`
	TargetType string        `json:"target_type"`
	Passed     bool          `json:"passed"`
	Checks     []checkResult `json:"checks"`
}

// 仅发 TCP；接入段凭据从私有配置读取，不接受 URL 或命令行口令。
func runSOCKS(args []string) error {
	flags := flag.NewFlagSet("socks", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", "", "已启用 SOCKS5 的测试配置")
	resultPath := flags.String("result", "", "新的脱敏结果文件")
	runID := flags.String("run-id", "", "请求关联标识")
	host := flags.String("host", "", "已授权并指向测试目标的实际域名；缺省使用目标 IPv4")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *path == "" || *resultPath == "" || !validRunID(*runID) {
		return errors.New("SOCKS 测试参数无效")
	}
	cfg, err := config.LoadForClient(*path)
	if err != nil || !cfg.SOCKS5.Enabled {
		return errors.New("SOCKS 测试配置无效或端点未启用")
	}
	target, err := targetFromEnvironment()
	if err != nil {
		return err
	}
	address, targetType := httpTarget(target).String(), "ipv4"
	if *host != "" {
		name, ok := domain.Normalize(*host, false)
		if !ok {
			return errors.New("测试域名无效")
		}
		if _, err := netip.ParseAddr(name); err == nil {
			return errors.New("host 参数须为实际域名")
		}
		address, targetType = net.JoinHostPort(name, strconv.Itoa(httpPort)), "domain"
	}
	proxy := socksURL(cfg)
	report := probeSOCKS(context.Background(), proxy, address, targetType, *runID, probeBudgets{request: requestBudget, transfer: transferBudget})
	if err := writeResult(*resultPath, report); err != nil {
		return err
	}
	if !report.Passed {
		return errors.New("SOCKS TCP 流量校验失败，详见脱敏结果")
	}
	return nil
}

func probeSOCKS(ctx context.Context, proxy *url.URL, address, targetType, runID string, budgets probeBudgets) (report socksReport) {
	report = socksReport{RunID: runID, TargetType: targetType, Checks: []checkResult{}}
	for _, check := range httpChecks(budgets) {
		transport := socksTransport(proxy)
		result := measureHTTP(ctx, transport, nil, address, runID, check.budget, check.name, check.method, check.path, check.digest, check.size)
		report.Checks = append(report.Checks, result)
		if !result.Passed {
			return report
		}
	}
	report.Passed = true
	return report
}

func socksURL(cfg *config.Config) *url.URL {
	proxy := &url.URL{Scheme: "socks5h", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.SOCKS5.ListenPort))}
	if cfg.SOCKS5.Username != "" {
		proxy.User = url.UserPassword(cfg.SOCKS5.Username, cfg.SOCKS5.Password)
	}
	return proxy
}

func socksTransport(proxy *url.URL) *http.Transport {
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true, MaxConnsPerHost: 1}
	transport.DialContext = func(ctx context.Context, network, destination string) (net.Conn, error) {
		if network != "tcp" || destination != proxy.Host {
			return nil, errors.New("拒绝绕过 SOCKS 的测试连接")
		}
		return (&net.Dialer{}).DialContext(ctx, network, destination)
	}
	return transport
}
