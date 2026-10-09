package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/socks5"
	"github.com/libra0037/nju-vpn/internal/ztna"
)

type proxyTestStream struct{ *net.TCPConn }

func (s *proxyTestStream) BoundAddress() (string, uint16) { return "198.51.100.9", 40000 }

func TestSOCKSProbeCarriesVerifiedHTTPWithoutLocalTargetDNS(t *testing.T) {
	for _, tc := range []struct {
		kind, host    string
		auth, badAuth bool
	}{
		{"ipv4", "192.0.2.1", false, false},
		{"domain", "resource.example.edu", false, false},
		{"domain-auth", "resource.example.edu", true, false},
		{"auth-rejected", "resource.example.edu", true, true},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
					w.Write(payload(8388608, 256))
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
			}))
			t.Cleanup(backend.Close)
			opts := socks5.Options{MaxConnections: 8, MaxDials: 2}
			if tc.auth {
				opts.Username, opts.Password = "proxy-user", "proxy-secret"
			}
			proxy, err := socks5.New("127.0.0.1:0", opts)
			if err != nil {
				t.Fatal(err)
			}
			address := net.JoinHostPort("127.0.0.1", strconv.Itoa(proxy.Diagnostics().Port))
			entry := &url.URL{Scheme: "socks5h", Host: address}
			if tc.auth {
				password := opts.Password
				if tc.badAuth {
					password = "wrong-password"
				}
				entry.User = url.UserPassword(opts.Username, password)
			}
			wantTarget, err := ztna.NewTCPTarget(tc.host, 18080)
			if err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			done := make(chan error, 1)
			go func() {
				done <- proxy.Run(t.Context(), func(ctx context.Context, target ztna.TCPTarget) (socks5.Stream, error) {
					calls.Add(1)
					if target != wantTarget {
						return nil, errors.New("SOCKS 请求失去实际域名或目标端口")
					}
					connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", backend.Listener.Addr().String())
					if err != nil {
						return nil, err
					}
					return &proxyTestStream{connection.(*net.TCPConn)}, nil
				})
			}()
			t.Cleanup(func() {
				proxy.Close()
				if err := <-done; err != nil {
					t.Error("SOCKS 测试接入任务未正常退出")
				}
			})
			<-proxy.Started()
			targetType := "domain"
			if tc.kind == "ipv4" {
				targetType = "ipv4"
			}
			report := probeSOCKS(t.Context(), entry, net.JoinHostPort(tc.host, "18080"), targetType, testRunID, probeBudgets{request: 3 * time.Second, transfer: 10 * time.Second})
			if tc.badAuth {
				if report.Passed || len(report.Checks) != 1 || calls.Load() != 0 {
					t.Fatal("认证失败后绕过 SOCKS 或继续发送测试流量", report)
				}
			} else {
				if !report.Passed || len(report.Checks) != 3 || calls.Load() != 3 {
					t.Fatal("SOCKS 完整 TCP 样例未通过", report)
				}
				for i, size := range []int64{20, 8388608, 1048576} {
					if report.Checks[i].Bytes != size || !report.Checks[i].Passed {
						t.Fatal("固定正文长度与摘要校验失败", report.Checks[i])
					}
				}
			}
			encoded, err := json.Marshal(report)
			if err != nil || strings.Contains(string(encoded), "proxy-secret") || strings.Contains(string(encoded), tc.host) || strings.Contains(string(encoded), "proxy-user") {
				t.Fatal("结果记录泄露凭据或业务地址")
			}
		})
	}
}
