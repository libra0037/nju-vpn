package ztna

import (
	"strings"
	"testing"
)

func TestSixtyKiBResourceResponseFitsAfterNormalization(t *testing.T) {
	const app = `{"id":"app","nodeGroupId":"g","accessModel":"L3VPN","addressList":[{"host":"192.0.2.1","protocol":"tcp","port":"443"}]}`
	raw := []byte(`{"data":{"appList":{"data":{"appInfo":[{"apps":[` +
		strings.TrimSuffix(strings.Repeat(app+",", 512), ",") + `]}]}}}}`)
	if len(raw) != 61494 {
		t.Fatal("固定原始样例长度改变", len(raw))
	}
	table, _, err := parseResourceTable(raw, "vpn.test")
	if err != nil {
		t.Fatal(err)
	}
	resources := table.view()
	if len(resources.IP) != 512 || resources.TCPDomains == nil {
		t.Fatal("快照丢失规则或元数据")
	}

	for _, rule := range resources.IP {
		if rule.Prefix.String() != "192.0.2.1/32" || rule.Protocol != ResourceProtocolTCP || rule.Ports != [2]uint16{443, 443} {
			t.Fatal("归一化字段错误", rule)
		}
	}
}
