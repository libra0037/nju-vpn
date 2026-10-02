package ztna

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSixtyKiBResourceResponseExpandsPastCommandBudget(t *testing.T) {
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
	body, err := table.snapshotJSON(8 << 20)
	if err != nil || len(body) != 66561 {
		t.Fatal("固定快照编码长度错误", err, len(body))
	}
	var list []Resource
	if err := json.Unmarshal(body, &list); err != nil || len(list) != 512 {
		t.Fatal("快照丢失资源", err, len(list))
	}
}
