package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/libra0037/nju-vpn/internal/ipc"
)

func TestLogEventsKeepOnlyFixedCategoriesAndNumbers(t *testing.T) {
	const prefix = "2026/10/02 12:34:56 "
	cases := []struct {
		message string
		kind    string
		reason  string
		count   uint64
		pid     uint64
	}{
		{`njuvpn 服务进程启动 pid=42 账号="private-user" 配置="secret-path"`, "service_started", "", 0, 42},
		{"隧道连接已建立", "tunnel_established", "", 0, 0},
		{"隧道断开: secret-token at 192.0.2.1:443", "tunnel_closed", "", 0, 0},
		{"逐流鉴权暂未就绪（状态 0x86），已安排 10s 后的一次重试", "auth_retry", "", 0, 0},
		{"wireguard: 丢弃 下行队列已满（累计 19 个）", "relay_drop", "downlink_full", 19, 0},
		{"上行拒绝：分片乱序或重叠，累计 7 个包", "tunnel_reject", "fragment_order", 7, 0},
		{"上行拒绝：待鉴权缓存已满，累计 64 个包", "tunnel_reject", "pending_full", 64, 0},
	}
	for _, tc := range cases {
		event, ok := parseLogEvent(prefix + tc.message)
		if !ok || event.Kind != tc.kind || event.Reason != tc.reason || event.Count != tc.count || event.PID != tc.pid {
			t.Fatalf("固定日志分类错误: %+v, %v", event, ok)
		}
		body, err := json.Marshal(event)
		if err != nil || strings.Contains(string(body), "private-") || strings.Contains(string(body), "secret-") || strings.Contains(string(body), "192.0.2.1") {
			t.Fatal("日志事件没有脱敏")
		}
	}
	for _, line := range []string{
		"2026/99/02 12:34:56 隧道连接已建立",
		prefix + "njuvpn test-version 服务进程启动 pid=42 账号=private-user",
		prefix + "njuvpn 服务进程启动 pid=18446744073709551616 账号=private-user",
		prefix + "wireguard: 丢弃 secret-token（累计 1 个）",
		prefix + "wireguard: 丢弃 下行队列已满（累计 18446744073709551616 个）",
		prefix + "上行拒绝：secret-token，累计 1 个包",
		prefix + "隧道连接已建立 private-user",
		"secret-token",
	} {
		if _, ok := parseLogEvent(line); ok {
			t.Fatal("错误接受未知、溢出或无效日期的日志")
		}
	}
}

func TestLogSummarySelectsInstanceAndKeepsLatestBoundedEvents(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "测试 配置.yaml")
	logPath := filepath.Join(directory, "njuvpn-"+ipc.InstanceTag(configPath)+"-config.log")
	const startup = "2026/10/02 12:34:00 njuvpn 服务进程启动 pid=42 账号=private-user\n"
	if err := os.WriteFile(logPath+".2", []byte(startup), 0600); err != nil {
		t.Fatal(err)
	}
	var body strings.Builder
	for i := 1; i <= 300; i++ {
		fmt.Fprintf(&body, "2026/10/02 12:34:56 wireguard: 丢弃 下行队列已满（累计 %d 个）\n", i)
	}
	original := body.String()
	if err := os.WriteFile(logPath, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "njuvpn-other-config.log"), []byte(startup+"secret-token"), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := collectLogSummary(configPath)
	if err != nil || !result.Found || result.FilesScanned != 2 || len(result.Events) != 256 || result.EventsOmitted != 45 {
		t.Fatalf("日志范围或事件上限错误: %+v, %v", result, err)
	}
	if result.Events[0].Count != 45 || result.Events[255].Count != 300 || result.Events[255].PID != 42 {
		t.Fatal("保留的事件顺序、截断位置或进程归属错误")
	}
	if result.BytesScanned != int64(len(startup)+len(original)) {
		t.Fatal("读取字节数错误")
	}
	after, err := os.ReadFile(logPath)
	if err != nil || string(after) != original {
		t.Fatal("摘要操作修改了日志")
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), directory) || strings.Contains(string(encoded), "private-user") || strings.Contains(string(encoded), "secret-token") {
		t.Fatal("日志摘要泄露路径或原文")
	}
}

func TestLogSummaryRejectsAmbiguityAndResourceOverflow(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		result, err := collectLogSummary(filepath.Join(t.TempDir(), "config.yaml"))
		if err != nil || result.Found || len(result.Events) != 0 {
			t.Fatal("未找到日志被误记为找到或有事件")
		}
	})
	for _, mode := range []string{"ambiguous", "oversized", "long-line", "directory", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			directory := t.TempDir()
			configPath := filepath.Join(directory, "config.yaml")
			prefix := "njuvpn-" + ipc.InstanceTag(configPath) + "-"
			path := filepath.Join(directory, prefix+"config.log")
			var err error
			switch mode {
			case "directory":
				err = os.Mkdir(path, 0700)
			case "symlink":
				original := filepath.Join(directory, "original.log")
				if err = os.WriteFile(original, []byte("secret-token"), 0600); err == nil {
					err = os.Symlink(original, path)
					if err != nil {
						t.Skip("当前权限不能创建符号链接")
					}
				}
			default:
				body := []byte("2026/10/02 12:34:56 隧道连接已建立\n")
				if mode == "oversized" {
					body = make([]byte, 4*1024*1024+1)
				} else if mode == "long-line" {
					body = make([]byte, 8193)
				}
				err = os.WriteFile(path, body, 0600)
				if err == nil && mode == "ambiguous" {
					err = os.WriteFile(filepath.Join(directory, prefix+"other.log"), body, 0600)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := collectLogSummary(configPath); err == nil || strings.Contains(err.Error(), directory) {
				t.Fatal("没有拒绝非法、无界或混合的日志输入，或错误泄露路径")
			}
		})
	}
	t.Run("too-many-entries", func(t *testing.T) {
		directory := t.TempDir()
		for i := 0; i < 257; i++ {
			if err := os.WriteFile(filepath.Join(directory, fmt.Sprint(i)), nil, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := collectLogSummary(filepath.Join(directory, "config.yaml")); err == nil {
			t.Fatal("日志目录超过数量上限仍被接受")
		}
	})
}
