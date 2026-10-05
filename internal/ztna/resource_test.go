package ztna

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestResourceRulePriorityAndCompleteMatching(t *testing.T) {
	raw := []byte(`{"data":{"appList":{"data":{"appInfo":[{"apps":[
 {"id":"broad","nodeGroupId":"g","accessModel":"L3VPN","addressList":[{"host":"10.0.0.0/8","protocol":"all","port":"1-65535"}]},
 {"id":"exact-all","nodeGroupId":"g","accessModel":"L3VPN","addressList":[{"host":"10.1.2.3","protocol":"ALL","port":"443"}]},
 {"id":"exact-udp","nodeGroupId":"g","accessModel":"L3VPN","addressList":[{"host":"10.1.2.3","protocol":"UDP","port":"53"}]},
 {"id":"exact-tcp","nodeGroupId":"g","accessModel":"L3VPN","addressList":[{"host":"10.1.2.3","protocol":"tcp","port":"80"}]},
 {"id":"same-key","nodeGroupId":"g","accessModel":"L3VPN","addressList":[{"host":"10.1.2.3/32","protocol":"TCP","port":"80"}]},
 {"id":"subnet","nodeGroupId":"g","accessModel":"L3VPN","addressList":[{"host":"10.1.9.9/16","protocol":"tcp","port":"443"}]},
 {"id":"earlier-address","nodeGroupId":"g","accessModel":"L3VPN","addressList":[{"host":"10.1.2.2","protocol":"all","port":"1-65535"}]}]}]}}}}`)
	table, err := parseResourceTable(raw, "vpn.test")
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, rule := range table.IP {
		order = append(order, rule.ID)
	}
	wantOrder := []string{"earlier-address", "exact-udp", "exact-tcp", "same-key", "exact-all", "subnet", "broad"}
	if !slices.Equal(order, wantOrder) {
		t.Fatal("前缀、地址、协议或同键顺序错误", order)
	}
	for _, tc := range []struct {
		dst   string
		proto uint8
		port  uint16
		want  string
	}{
		{"10.1.2.3", protoUDP, 53, "exact-udp"},
		{"10.1.2.3", protoTCP, 80, "exact-tcp"},
		{"10.1.2.3", protoTCP, 443, "exact-all"},
		{"10.1.2.3", protoUDP, 443, "exact-all"},
		{"10.1.2.3", protoTCP, 22, "broad"},
		{"10.1.2.3", protoICMP, 0, "exact-all"},
		{"10.1.2.99", protoTCP, 443, "subnet"},
		{"10.1.2.99", protoUDP, 443, "broad"},
		{"10.1.2.2", protoTCP, 22, "earlier-address"},
		{"10.1.2.3", protoTCP, 0, ""},
		{"10.1.2.3", protoUDP, 0, ""},
		{"192.0.2.1", protoTCP, 443, ""},
		{"::ffff:10.1.2.3", protoTCP, 443, ""},
	} {
		dst := netip.MustParseAddr(tc.dst)
		app, group, ok := table.match(dst, tc.proto, tc.port)
		if app != tc.want || ok != (tc.want != "") || ok && group != "g" {
			t.Errorf("%s/%d/%d：%q/%q（%v），期望 %q", tc.dst, tc.proto, tc.port, app, group, ok, tc.want)
		}
	}
	dst := netip.MustParseAddr("10.1.2.3")
	if allocs := testing.AllocsPerRun(100, func() { table.match(dst, protoTCP, 443) }); allocs != 0 {
		t.Fatal("逐包匹配产生分配", allocs)
	}
}

func TestResourceDNSUsesV2AndRejectsInvalidAddresses(t *testing.T) {
	raw := []byte(`{"data":{"sdpPolicy":{"data":{"clientOption":{"dnsOption":{"firstDNS":"192.0.2.1"},"dnsOptionV2":{"firstDNS":"192.0.2.53","secondDNS":"192.0.2.54"}}}}}}`)
	table, err := parseResourceTable(raw, "vpn.test")
	if err != nil || table.DNS != (ResourceDNS{FirstDNS: "192.0.2.53", SecondDNS: "192.0.2.54"}) {
		t.Fatal("没有采用 V2 DNS 元数据", table, err)
	}
	for _, dns := range []string{"dns.example", "::1", "::ffff:192.0.2.53", "192.0.2.53\nmarker"} {
		raw := []byte(fmt.Sprintf(`{"data":{"sdpPolicy":{"data":{"clientOption":{"dnsOptionV2":{"firstDNS":%q}}}}}}`, dns))
		_, err := parseResourceTable(raw, "vpn.test")
		var protocolErr *ProtocolError
		if !errors.As(err, &protocolErr) || strings.Contains(err.Error(), dns) {
			t.Fatal("非法 DNS 未拒绝或泄露值", err)
		}
	}
}

func TestResourceNodeGroupsAreStableWANFirstAndDeduplicateCandidates(t *testing.T) {
	raw := []byte(`{"data":{"appList":{"data":{"config":{"nodeGroupConf":{"majorNodeGroup":{"id":"main"},"nodeGroupList":[
 {"id":"z","addressInfo":[{"address":"z.test:441","type":"wan"}]},
 {"id":"main","addressInfo":[{"address":"lan.test:441","type":"lan"},{"address":"wan1.test:441","type":"WAN"},{"address":"wan2.test:441","type":"wan"}]},
 {"id":"a","addressInfo":[{"address":"a.test:441","type":"wan"},{"address":"wan1.test:441","type":"wan"}]},
 {"id":"preferred","addressInfo":[{"address":"peer.test:441","type":"lan"}]}]}}}}}}`)
	table, err := parseResourceTable(raw, "vpn.test")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"peer.test:441", "wan1.test:441", "wan2.test:441", "lan.test:441", "a.test:441", "z.test:441"}
	for range 10 {
		if got := table.candidateNodes("preferred"); !slices.Equal(got, want) {
			t.Fatal("节点组顺序不稳定、WAN 未优先或候选重复", got)
		}
	}
	if nodes := table.NodeGroup["main"]; len(nodes) != 3 || nodes[0].Address != "wan1.test:441" || nodes[0].Type != "wan" || nodes[2].Type != "lan" {
		t.Fatal("节点状态没有归一化", nodes)
	}
}

func TestResourceCountsAndLengthsRemainBounded(t *testing.T) {
	for name, raw := range map[string]string{
		"apps":      `{"data":{"appList":{"data":{"appInfo":[{"apps":[` + strings.TrimSuffix(strings.Repeat(`{"id":"a"},`, 4097), ",") + `]}]}}}}`,
		"addresses": `{"data":{"appList":{"data":{"appInfo":[{"apps":[{"addressList":[` + strings.TrimSuffix(strings.Repeat(`{"host":"x"},`, 16385), ",") + `]}]}]}}}}`,
		"groups":    `{"data":{"appList":{"data":{"config":{"nodeGroupConf":{"nodeGroupList":[` + strings.TrimSuffix(strings.Repeat(`{"id":"g"},`, 257), ",") + `]}}}}}}`,
		"nodes":     `{"data":{"appList":{"data":{"config":{"nodeGroupConf":{"nodeGroupList":[{"id":"g","addressInfo":[` + strings.TrimSuffix(strings.Repeat(`{"address":"node.test:441","type":"wan"},`, 257), ",") + `]}]}}}}}}`,
		"host":      `{"data":{"appList":{"data":{"appInfo":[{"apps":[{"addressList":[{"host":"` + strings.Repeat("x", 1025) + `"}]}]}]}}}}`,
		"protocol":  `{"data":{"appList":{"data":{"appInfo":[{"apps":[{"addressList":[{"protocol":"` + strings.Repeat("x", 65) + `"}]}]}]}}}}`,
		"port":      `{"data":{"appList":{"data":{"appInfo":[{"apps":[{"addressList":[{"port":"` + strings.Repeat("x", 257) + `"}]}]}]}}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseResourceTable([]byte(raw), "vpn.test"); err == nil {
				t.Fatal("超预算输入仍接受")
			}
		})
	}
}
