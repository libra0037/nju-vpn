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
	"net/netip"
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
func TestResourceSnapshotContainsOnlyNormalizedStateAndIsIndependent(t *testing.T) {
	raw := []byte(`{"data":{"appList":{"data":{"appInfo":[{"apps":[
 {"id":"domain","accessModel":"L3VPN","nodeGroupId":"g","addressList":[{"host":"db.example","protocol":"tcp","port":"443","ip":["10.1.2.3"]}]},
 {"id":"empty","accessModel":"","nodeGroupId":"g","addressList":[{"host":"192.0.2.1","protocol":"all","port":"1-65535"}]},
 {"id":"web","accessModel":"WEB","addressList":[{"host":"192.0.2.2","protocol":"tcp","port":"443"}]},
 {"id":"ip","accessModel":"L3VPN","nodeGroupId":"g","addressList":[{"host":"10.1.2.7/24","protocol":"TCP","port":"443"}]}]}],
 "config":{"nodeGroupConf":{"majorNodeGroup":{"id":"g"},"nodeGroupList":[{"id":"g","addressInfo":[{"address":"node.test:441","type":"wan"}]}]}}}},
 "sdpPolicy":{"data":{"clientOption":{"dnsOptionV2":{"firstDNS":"10.0.0.53","secondDNS":"10.0.0.54"}}}}}}`)
	table, err := parseResourceTable(raw, "vpn.test")
	if err != nil {
		t.Fatal(err)
	}
	snapshot := func() L3Resources {
		b, err := table.snapshotJSON(65536)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "db.example") || strings.Contains(string(b), "addressList") {
			t.Fatal("快照保留了原始资源树")
		}
		var result L3Resources
		if err := json.Unmarshal(b, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	snap := snapshot()
	if len(snap.IP) != 1 || snap.IP[0].ID != "ip" || snap.IP[0].Host.String() != "10.1.2.0/24" || snap.DNS.FirstDNS != "10.0.0.53" {
		t.Fatal("筛选或归一化错误", snap)
	}
	if app, _, ok := table.match(netip.MustParseAddr("10.1.2.3"), protoTCP, 443); !ok || app != "ip" {
		t.Fatal("没有按显式 IP 资源鉴权", app, ok)
	}
	snap.IP[0].ID = "changed"
	snap.IP[0].Port[0] = 1
	snap.DNS.FirstDNS = "changed"
	snap.NodeGroup["g"][0].Address = "changed"
	again := snapshot()
	if again.IP[0].ID != "ip" || again.IP[0].Port != [2]uint16{443, 443} || again.DNS.FirstDNS != "10.0.0.53" || again.NodeGroup["g"][0].Address != "node.test:441" {
		t.Fatal("IPC 消费者污染了会话状态")
	}
	empty, err := parseResourceTable([]byte(`{}`), "vpn.test")
	if err != nil {
		t.Fatal(err)
	}
	body, err := empty.snapshotJSON(65536)
	if err != nil || string(body) != `{"ip":[],"dns":{"firstDNS":"","secondDNS":""},"nodegroup":{}}` {
		t.Fatal("空资源对象格式改变", string(body), err)
	}
}

func TestDomainIPsNeverCreateAnAccessRule(t *testing.T) {
	raw := []byte(`{"data":{"appList":{"data":{"appInfo":[{"apps":[{"id":"domain","accessModel":"L3VPN","addressList":[{"host":"db.example","protocol":"tcp","port":"443","ip":["192.0.2.1"]}]}]}]}}}}`)
	table, err := parseResourceTable(raw, "vpn.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(table.IP) != 0 {
		t.Fatal("域名附带 IP 被转成规则")
	}
	if _, _, ok := table.match(netip.MustParseAddr("192.0.2.1"), protoTCP, 443); ok {
		t.Fatal("仅有域名资源仍允许访问附带 IP")
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
