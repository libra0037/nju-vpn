package main

import (
	"strings"
	"testing"
)

func TestTargetIPBoundaryAndRedaction(t *testing.T) {
	for _, value := range []string{"", "::1", "127.0.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255", "192.0.2.1:80", "192.0.2.1/32", "marker-secret-host"} {
		_, err := parseTargetIP(value)
		if err == nil || strings.Contains(err.Error(), "marker-secret-host") {
			t.Fatalf("未拒绝非法目标或回显输入；错误=%v", err)
		}
	}
	for _, value := range []string{"192.0.2.1", "10.0.0.1"} {
		target, err := parseTargetIP(value)
		if err != nil || target.String() != value || httpTarget(target).Port() != 18080 {
			t.Fatal("有效目标或固定测试端口不符")
		}
	}
	t.Setenv("NJUVPN_TEST_TARGET_IP", "198.51.100.1")
	target, err := targetFromEnvironment()
	if err != nil || target.String() != "198.51.100.1" {
		t.Fatal("入口未使用显式配置目标")
	}
}
