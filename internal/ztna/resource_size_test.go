package ztna

import (
	"encoding/json"
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
	table, err := parseResourceTable(raw, "vpn.test")
	if err != nil {
		t.Fatal(err)
	}
	body, err := table.snapshotJSON(65536 - len("200 \n"))
	if err != nil {
		t.Fatal("约 60 KiB 输入未能归一化到统一响应预算", err)
	}
	var resources L3Resources
	if err := json.Unmarshal(body, &resources); err != nil || len(resources.IP) != 512 || resources.NodeGroup == nil {
		t.Fatal("快照丢失规则或元数据结构", err)
	}
	for _, rule := range resources.IP {
		if rule.ID != "app" || rule.Host.String() != "192.0.2.1/32" || rule.Protocol != ResourceProtocolTCP || rule.Port != [2]uint16{443, 443} {
			t.Fatal("归一化字段错误", rule)
		}
	}
}
