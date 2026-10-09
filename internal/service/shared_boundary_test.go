package service

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/ipc"
	"github.com/libra0037/nju-vpn/internal/ztnatest"
)

func TestPasswordPreservesLeadingAndTrailingSpaces(t *testing.T) {
	const password = " secret "
	srv := newFakeServer(t, ztnatest.Options{Password: password})
	cfg := newTestConfig(t, srv)
	cfg.Password = password
	svc := newTestService(t, srv, cfg)
	if err := svc.Start(false, ""); err != nil {
		t.Fatalf("合法口令的首尾空格被删除: %v", err)
	}
}
func TestStatusRejectsWhileLogoutIsBlocked(t *testing.T) {
	srv := newFakeServer(t, ztnatest.Options{})
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce, enterOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	upstreamTransport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: srv.RootCAs(), MinVersion: tls.VersionTLS12}}
	upstream := &http.Client{Transport: upstreamTransport, Timeout: 3 * time.Second}
	defer upstreamTransport.CloseIdleConnections()
	control := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/passport/v1/user/logout" {
			enterOnce.Do(func() { close(entered) })
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		req, err := http.NewRequestWithContext(r.Context(), r.Method, "https://"+srv.Addr()+r.URL.RequestURI(), r.Body)
		if err != nil {
			http.Error(w, "request", 500)
			return
		}
		req.Header = r.Header.Clone()
		resp, err := upstream.Do(req)
		if err != nil {
			http.Error(w, "upstream", 500)
			return
		}
		defer resp.Body.Close()
		for name, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	defer control.Close()
	defer unblock()
	u, err := url.Parse(control.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	cfg := newTestConfig(t, srv)
	cfg.Server, cfg.ServerIP, cfg.Port = "example.com", host, port
	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == u.Host {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
		return srv.Dial(ctx, network, addr)
	}
	roots := control.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	svc, err := New(cfg, Options{Dial: dialer, ControlRootCAs: roots, ReconnectBackoff: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	defer unblock()
	if err := svc.Start(false, ""); err != nil {
		t.Fatal(err)
	}
	stopped := make(chan error, 1)
	go func() { stopped <- svc.Stop() }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("未到达登出等待点")
	}
	for _, args := range [][]string{nil, {"json"}} {
		server := NewServer(svc, nil)
		resp := server.dispatch(ipc.Request{Command: ipc.CmdStatus, Args: args})
		if resp.Code != ipc.CodeRejected {
			t.Errorf("隧道已拆除但 status 返回 %d: %s", resp.Code, resp.Message)
		}
	}
	unblock()
	select {
	case err := <-stopped:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Stop 未结束")
	}
}
