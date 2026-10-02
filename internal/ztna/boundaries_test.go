package ztna

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/ztnatest"
)

type responseTransport func(*http.Request) (*http.Response, error)

func (f responseTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func responseControl(t *testing.T, body string) *control {
	t.Helper()
	c, err := newControl(controlOptions{Server: "vpn.test", DialAddr: "vpn.test:443", Dial: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("禁止联网") }})
	if err != nil {
		t.Fatal(err)
	}
	c.hc.Transport = responseTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	return c
}
func TestControlRejectsMissingCodeAndRedactsResponseValues(t *testing.T) {
	for _, s := range []string{`{"data":{"ticket":"marker"}}`, `{"code":null,"data":{}}`, `{"code":"0","data":{}}`, `{"code":0}`, `{"code":0,"data":null}`} {
		if _, err := envelopeData([]byte(s)); err == nil {
			t.Fatal("接受缺失或错误字段", s)
		}
	}
	marker := "private-token-marker"
	c := responseControl(t, `{"code":0,"data":{"csrfToken":"`+marker+`","authServerInfoList":42}}`)
	_, err := c.authConfig(t.Context(), true)
	if err == nil || strings.Contains(err.Error(), marker) {
		t.Fatal("错误未拒绝或泄露响应值", err)
	}
	for _, code := range []int{75500000, 75500002, 75509999} {
		_, err := envelopeData([]byte(fmt.Sprintf(`{"code":%d,"message":"%s","data":{}}`, code, marker)))
		if err == nil || strings.Contains(err.Error(), marker) {
			t.Fatal("泄露服务端文案", err)
		}
	}
}
func TestControlHTTPResponseBudget(t *testing.T) {
	c := responseControl(t, strings.Repeat("x", maxControlBytes+1))
	if _, err := c.do(t.Context(), http.MethodGet, pathManifest, nil, nil, nil); err == nil {
		t.Fatal("响应超出 8 MiB 仍接受")
	}
}
func TestResourceSnapshotPreservesAdvertisementAndCopiesAllSlices(t *testing.T) {
	raw := []byte(`{"code":0,"data":{"appList":{"data":{"appInfo":[{"apps":[
 {"id":"domain","accessModel":"L3VPN","nodeGroupId":"g","addressList":[{"host":"db.example","protocol":"CUSTOM","port":"many","ip":["10.1.2.3","10.1.2.4"]}]},
 {"id":"empty","accessModel":"","nodeGroupId":"g","addressList":[]},
 {"id":"web","accessModel":"WEB","addressList":[{"host":"x"}]},
 {"id":"ip","accessModel":"L3VPN","nodeGroupId":"g","addressList":[{"host":"10.1.2.0/24","protocol":"tcp","port":"443","ip":[]}]}] }]}}}} `)
	table, err := parseResourceTable(raw, "vpn.test")
	if err != nil {
		t.Fatal(err)
	}
	snapshot := func() []Resource {
		b, err := table.snapshotJSON(65536)
		if err != nil {
			t.Fatal(err)
		}
		var s []Resource
		if err := json.Unmarshal(b, &s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	snap := snapshot()
	if len(snap) != 3 || snap[0].ID != "domain" || snap[1].AccessModel != "" || len(snap[1].AddressList) != 0 || len(table.entries) != 1 {
		t.Fatal("筛选丢失原始应用或误扩展匹配", snap)
	}
	snap[0].ID = "changed"
	snap[0].AddressList[0].Host = "changed"
	snap[0].AddressList[0].IP[0] = "changed"
	again := snapshot()
	if again[0].ID != "domain" || again[0].AddressList[0].Host != "db.example" || again[0].AddressList[0].IP[0] != "10.1.2.3" {
		t.Fatal("快照污染会话资源")
	}
	body, _ := (&resourceTable{}).snapshotJSON(2)
	if string(body) != "[]" {
		t.Fatal("空列表应为成功的 []")
	}
}
func TestResourceInputBudgetsAndVIPFields(t *testing.T) {
	for _, raw := range []string{
		strings.Repeat("[", 33) + "0" + strings.Repeat("]", 33),
		`{"data":{"appList":{"data":{"appInfo":[{"apps":[{"id":"` + strings.Repeat("a", 129) + `"}]}]}}}}`,
	} {
		if _, err := parseResourceTable([]byte(raw), "vpn.test"); err == nil {
			t.Fatal("超预算资源仍接受")
		}
	}
	vip := parseVIPListPayload([]byte(`{"code":0,"data":{"dns":"8.8.8.8","vip":"172.16.0.9"}}`))
	if len(vip) != 1 || vip[0].String() != "172.16.0.9" {
		t.Fatal("DNS 被当作 VIP", vip)
	}
	if got := parseVIPListPayload([]byte(`{"code":0,"data":{"dns":"8.8.8.8"}}`)); len(got) != 0 {
		t.Fatal("无关地址被采纳", got)
	}
}
func TestProbesBoundedAndJoinedOnSuccess(t *testing.T) {
	srv := newFake(t, ztnatest.Options{})
	var active, peak atomic.Int32
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	fn := func(ctx context.Context, _ string) (*tls.Conn, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		select {
		case entered <- struct{}{}:
		default:
		}
		select {
		case <-release:
			return dialNodeTLS(ctx, tunnelOptions{Node: srv.Addr(), Server: "vpn.test", Dial: srv.Dial, Pins: newNodeSPKIPins([][32]byte{srv.SPKIPin()})})
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	addrs := make([]string, 256)
	for i := range addrs {
		addrs[i] = fmt.Sprintf("node-%d:441", i)
	}
	done := make(chan struct{})
	var err error
	var conn *tls.Conn
	var once sync.Once
	go func() { defer close(done); _, conn, err = probeNodes(t.Context(), fn, addrs, time.Second) }()
	for range 8 {
		awaitSignal(t, entered)
	}
	once.Do(func() { close(release) })
	awaitSignal(t, done)
	if conn != nil {
		conn.NetConn().Close()
	}
	if err != nil || active.Load() != 0 || peak.Load() > 8 {
		t.Fatal("探活未回收或超出并发上限", err, active.Load(), peak.Load())
	}
}
