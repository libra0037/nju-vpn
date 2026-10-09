package ztna

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestTCPResourceShapePriorityAndIsolation(t *testing.T) {
	// 固定样例保持校园下发层级：addrPretend 属于应用，addressList 只含地址属性。
	raw := []byte(`{"data":{"appList":{"data":{"appInfo":[{"apps":[
{"id":"ignored","accessModel":"anything","addrPretend":true,"addressList":[{"host":"10.1.2.3","protocol":"all"},{"host":"ignore.example","protocol":"all"}]},
{"id":"empty","accessModel":"","addressList":[{"host":"10.1.2.4","protocol":"all"}]},
{"id":"ip","nodeGroupId":"g","accessModel":"L3VPN","addressList":[{"host":"192.0.2.7/24","protocol":"all","port":"80-443"}]},
{"id":"broad","accessModel":"L3VPN","addrPretend":true,"addressList":[{"host":"*.Example.EDU.","protocol":"all","port":"0","ip":["198.51.100.9"]}]},
{"id":"specific","accessModel":"L3VPN","addressList":[{"host":"db.example.edu","protocol":"tcp","port":"443","ip":["198.51.100.1","::1","bad","198.51.100.1","198.51.100.2"]}]},
{"id":"tie","accessModel":"L3VPN","addrPretend":true,"addressList":[{"host":"db.example.edu","protocol":"all","port":"443"}]},
{"id":"middle","accessModel":"L3VPN","addrPretend":true,"addressList":[{"host":"a*b.example.edu","protocol":"tcp","port":"22"}]},
{"id":"more-specific","accessModel":"L3VPN","addrPretend":true,"addressList":[{"host":"*.research.example.edu","protocol":"tcp","port":"443"}]},
{"id":"bad-shapes","accessModel":"L3VPN","addressList":[{"host":"noip.example.edu","protocol":"tcp"},{"host":"v6.example.edu","protocol":"tcp","ip":["::1"]},{"host":"udp.example.edu","protocol":"udp"}]}
]}]}}}}`)
	table, stats, err := parseResourceTable(raw, "vpn.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(table.ipRules) != 1 || len(table.domainRules) != 5 || stats.skippedApps != 2 || stats.badIPs != 1 || stats.unsupportedIPs != 2 || stats.missingDialIPs != 2 {
		t.Fatal("规则或有限跳过计数错误", stats)
	}
	for _, tc := range []struct {
		host string
		port uint16
		app  string
		ips  []string
	}{
		{"192.0.2.8", 443, "ip", nil}, {"db.example.edu", 443, "specific", []string{"198.51.100.1", "198.51.100.2"}},
		{"DB.Example.EDU.", 80, "broad", nil}, {"example.edu", 443, "", nil},
		{"alpha.research.example.edu", 443, "more-specific", nil}, {"alpha.research.example.edu", 80, "broad", nil},
		{"a-long-b.example.edu", 22, "middle", nil}, {"198.51.100.1", 443, "", nil}, {"ignore.example", 443, "", nil}, {"10.1.2.3", 443, "", nil},
		{"noip.example.edu", 443, "broad", nil},
	} {
		target, err := NewTCPTarget(tc.host, tc.port)
		if err != nil {
			t.Fatal(err)
		}
		route, ok := table.matchTCP(target)
		var ips []string
		for _, ip := range route.dialIPs {
			ips = append(ips, ip.String())
		}
		if ok != (tc.app != "") || route.grant.appID != tc.app || !slices.Equal(ips, tc.ips) {
			t.Errorf("%s:%d got=%s/%v want=%s/%v", tc.host, tc.port, route.grant.appID, ips, tc.app, tc.ips)
		}
		if tc.app == "ip" {
			grant, _ := table.matchIP(netip.MustParseAddr(tc.host), protoTCP, tc.port)
			if grant != route.grant {
				t.Fatal("两入口授权不一致")
			}
		}
	}
	for _, tc := range []struct {
		pattern, host string
		want          bool
	}{
		{"*.example.edu", "x.y.example.edu", true}, {"*.example.edu", "example.edu", false},
		{"a*b*c.example.edu", "abxxc.example.edu", true}, {"a*b*c.example.edu", "acb.example.edu", false},
		{"ab*bc", "abc", false}, {"*abc*abc", "abc", false}, {"*abc*abc", "abcabc", true},
		{"*", "any.example.edu", true}, {"exact.example.edu", "x.exact.example.edu", false},
	} {
		if domainPattern(tc.pattern).matches(tc.host) != tc.want {
			t.Fatal("通配语义错误", tc)
		}
	}
	target, _ := NewTCPTarget("db.example.edu", 443)
	if n := testing.AllocsPerRun(100, func() { table.matchTCP(target) }); n != 0 {
		t.Fatal("TCP 匹配分配", n)
	}
}

func TestTCPTargetAndEmptyTableRejectInvalidValues(t *testing.T) {
	for _, host := range []string{"", "::1", "::ffff:192.0.2.1", "https://x.example", "x:443", "x..edu", "-x.edu", "x-.edu", "x*.edu", "x.edu..", "中文.edu", strings.Repeat("a", 64) + ".edu", "x\n.edu"} {
		if _, err := NewTCPTarget(host, 443); err == nil {
			t.Fatal("非法目标被接受", host)
		}
	}
	if _, err := NewTCPTarget("valid.example", 0); err == nil {
		t.Fatal("零端口被接受")
	}
	var table resourceTable
	target, _ := NewTCPTarget("192.0.2.1", 443)
	if _, ok := table.matchTCP(target); ok || len(table.candidateNodes("")) != 0 {
		t.Fatal("零表产生授权")
	}
}

func TestTargetIPv4ClassifierAgreesWithStandardLibrary(t *testing.T) {
	hosts := []string{"0.0.0.0", "255.255.255.255", "192.0.2.1", "123", "1.2.3", "1.2.3.4.5", "001.2.3.4", "256.2.3.4", "123456.2.3.4", "123.example.edu", "123.2.3.example.edu", "0000.2.3.4"}
	for _, host := range hosts {
		want, err := netip.ParseAddr(host)
		got := targetIPv4(host)
		if got.IsValid() != (err == nil && want.Is4()) || got.IsValid() && got != want {
			t.Fatal("目标类别与标准库不一致", host)
		}
	}
}

func TestResourceNewFieldLimitsApplyToSkippedApps(t *testing.T) {
	for _, model := range []string{"L3VPN", "ignored"} {
		for name, field := range map[string]string{
			"ips":     `"ip":[` + strings.TrimSuffix(strings.Repeat(`"192.0.2.1",`, 65), ",") + `]`,
			"ip-text": `"ip":["` + strings.Repeat("x", 65) + `"]`,
			"ip-type": `"ip":"192.0.2.1"`,
		} {
			raw := fmt.Sprintf(`{"data":{"appList":{"data":{"appInfo":[{"apps":[{"id":"a","accessModel":%q,"addressList":[{%s}]}]}]}}}}`, model, field)
			if table, _, err := parseResourceTable([]byte(raw), "vpn.test"); err == nil || table != nil {
				t.Fatal("跳过模型放宽边界", model, name)
			}
		}
		raw := fmt.Sprintf(`{"data":{"appList":{"data":{"appInfo":[{"apps":[{"id":"a","accessModel":%q,"addrPretend":"true","addressList":[]}]}]}}}}`, model)
		if table, _, err := parseResourceTable([]byte(raw), "vpn.test"); err == nil || table != nil {
			t.Fatal("应用拨号策略类型错误仍被接受", model)
		}
	}
	const address = `{"host":"192.0.2.1","protocol":"tcp","port":"443"}`
	for _, count := range []int{maxResourceAddresses, maxResourceAddresses + 1} {
		raw := `{"data":{"appList":{"data":{"appInfo":[{"apps":[{"id":"a","accessModel":"L3VPN","addressList":[` + strings.TrimSuffix(strings.Repeat(address+",", count), ",") + `]}]}]}}}}`
		table, _, err := parseResourceTable([]byte(raw), "vpn.test")
		if count == maxResourceAddresses {
			if err != nil || len(table.ipRules) != count {
				t.Fatal("恰好达到地址预算被拒绝", err)
			}
		} else if err == nil {
			t.Fatal("超限未拒绝")
		}
	}
}

func BenchmarkDomainResourceMatch(b *testing.B) {
	for _, n := range []int{256, 16384} {
		for _, kind := range []string{"exact", "wildcard", "miss"} {
			b.Run(fmt.Sprintf("%s/%d", kind, n), func(b *testing.B) {
				rules := make([]tcpDomainRule, n)
				for i := range rules {
					rules[i] = tcpDomainRule{pattern: domainPattern(fmt.Sprintf("x%d.example.edu", i)), ports: portRange{1, 65535}, grant: resourceGrant{appID: "a"}}
				}
				host := "unknown.example.edu"
				if kind == "exact" {
					host = string(rules[n-1].pattern)
				}
				if kind == "wildcard" {
					rules[n-1].pattern = "*.research.example.edu"
					host = "db.research.example.edu"
				}
				table := resourceTable{domainRules: rules}
				target, _ := NewTCPTarget(host, 443)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					table.matchTCP(target)
				}
			})
		}
	}
}

func BenchmarkResourceParse(b *testing.B) {
	for _, n := range []int{837, 16384} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			const address = `{"host":"192.0.2.1","protocol":"tcp","port":"443"}`
			raw := []byte(`{"data":{"appList":{"data":{"appInfo":[{"apps":[{"id":"a","accessModel":"L3VPN","addressList":[` + strings.TrimSuffix(strings.Repeat(address+",", n), ",") + `]}]}]}}}}`)
			b.ReportAllocs()
			b.SetBytes(int64(len(raw)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, _, err := parseResourceTable(raw, "vpn.test"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkMaximumDomainPattern(b *testing.B) {
	suffix := "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	pattern := domainPattern(strings.Repeat("*a", 8) + strings.Repeat("a", 47) + suffix)
	target, err := NewTCPTarget(strings.Repeat("a", 63)+suffix, 443)
	if err != nil || !pattern.matches(target.host) {
		b.Fatal("最长域名夹具无效")
	}
	for _, n := range []int{256, 16384} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			rules := make([]tcpDomainRule, n)
			for i := range rules {
				rules[i] = tcpDomainRule{pattern: domainPattern(fmt.Sprintf("x%05d", i) + strings.Repeat("a", 57) + suffix), ports: portRange{1, 65535}}
			}
			rules[n-1].pattern = pattern
			table := resourceTable{domainRules: rules}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				table.matchTCP(target)
			}
		})
	}
}
