package main

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/libra0037/nju-vpn/internal/ipc"
)

const (
	maxLogReadBytes = 4 << 20 // 与候选程序单份日志的上限一致；至多读当前及两份备份。
	maxLogEvents    = 256
)

type logEvent struct {
	AtUTC  string `json:"at_utc"`
	Kind   string `json:"kind"`
	Reason string `json:"reason,omitempty"`
	Count  uint64 `json:"count,omitempty"`
	PID    uint64 `json:"pid,omitempty"`
}

type logSummary struct {
	Found         bool       `json:"found"`
	FilesScanned  int        `json:"files_scanned"`
	BytesScanned  int64      `json:"bytes_scanned"`
	EventsOmitted int        `json:"events_omitted"`
	Events        []logEvent `json:"events"`
}

// 只解析候选程序自身的固定日志契约；不输出原文、路径、身份或底层错误。
// 日志会限速且可能从备份中间开始，所以没有记录不等于没有发生丢包。
var relayLogReasons = map[string]string{
	"下行数据切不出 IPv4 包": "downlink_invalid",
	"下行包的目的地址不是本次分配到的地址（检查对端 allowed_ips 与 peer_address）": "downlink_address",
	"下行队列已满": "downlink_full",
	"会话已摘掉，下行包被丢弃（断开窗口里的尾巴）":               "downlink_no_session",
	"上行解出来的不是 IPv4 包":                      "uplink_invalid",
	"上行包的源地址不是 peer_address（对端 ip 配置不一致？）": "uplink_address",
	"对端尚未握手，下行包被丢弃（对端还没连上，或密钥不匹配）":         "peer_not_ready",
	"读缓冲装不下这个包":                            "no_buffer",
	"隧道尚未建立，对端发来的包被丢弃":                     "no_session",
	"隧道上行通道未就绪，包被丢弃":                       "no_uplink",
	"隧道拒绝了这个上行包":                           "uplink_rejected",
	"会话切换时丢掉了队列里属于旧会话的下行包（重连时正常）":          "stale_queue",
}

var rejectionLogReasons = map[string]string{
	"链路或会话不可用":   "link_unavailable",
	"资源表外":       "resource_unmatched",
	"流鉴权失败":      "flow_auth_failed",
	"待鉴权缓存已满":    "pending_full",
	"流表已满":       "flow_table_full",
	"分片关联不存在或过期": "fragment_missing",
	"分片乱序或重叠":    "fragment_order",
	"报文格式或容量超限":  "packet_capacity",
}

var relayLogPattern = regexp.MustCompile(`^wireguard: 丢弃 (.+)（累计 ([0-9]+) 个）$`)
var rejectionLogPattern = regexp.MustCompile(`^上行拒绝：(.+)，累计 ([0-9]+) 个包$`)
var startedLogPattern = regexp.MustCompile(`^njuvpn 服务进程启动 pid=([0-9]+) `)

func parseLogEvent(line string) (logEvent, bool) {
	if len(line) < 20 {
		return logEvent{}, false
	}
	stamp, err := time.ParseInLocation("2006/01/02 15:04:05 ", line[:20], time.Local)
	if err != nil {
		return logEvent{}, false
	}
	event := logEvent{AtUTC: stamp.UTC().Format(time.RFC3339)}
	message := line[20:]
	if match := startedLogPattern.FindStringSubmatch(message); match != nil {
		event.PID, err = strconv.ParseUint(match[1], 10, 64)
		event.Kind = "service_started"
		return event, err == nil
	}
	switch {
	case message == "隧道连接已建立":
		event.Kind = "tunnel_established"
	case strings.HasPrefix(message, "隧道断开: "):
		event.Kind = "tunnel_closed"
	case message == "逐流鉴权暂未就绪（状态 0x86），已安排 10s 后的一次重试":
		event.Kind = "auth_retry"
	default:
		match := relayLogPattern.FindStringSubmatch(message)
		reasons := relayLogReasons
		event.Kind = "relay_drop"
		if match == nil {
			match = rejectionLogPattern.FindStringSubmatch(message)
			reasons = rejectionLogReasons
			event.Kind = "tunnel_reject"
		}
		if match == nil || reasons[match[1]] == "" {
			return logEvent{}, false
		}
		event.Reason = reasons[match[1]]
		event.Count, err = strconv.ParseUint(match[2], 10, 64)
		if err != nil {
			return logEvent{}, false
		}
	}
	return event, true
}

func collectLogSummary(configPath string) (logSummary, error) {
	result := logSummary{Events: []logEvent{}}
	directory, err := os.Open(filepath.Dir(configPath))
	if err != nil {
		return result, errors.New("日志目录无法读取")
	}
	entries, readErr := directory.ReadDir(257)
	closeErr := directory.Close()
	if (readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil || len(entries) > 256 {
		return result, errors.New("日志目录读取失败或超过 256 项上限")
	}
	// 路径规范化和大小写规则来自产品的 InstanceTag；只选本配置的一个日志。
	prefix := "njuvpn-" + ipc.InstanceTag(configPath) + "-"
	var logPath string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), prefix) && strings.HasSuffix(entry.Name(), ".log") {
			if logPath != "" {
				return result, errors.New("本配置对应多个日志，拒绝混合实例")
			}
			logPath = filepath.Join(filepath.Dir(configPath), entry.Name())
		}
	}
	if logPath == "" {
		return result, nil
	}
	result.Found = true
	pid := uint64(0)
	var recent [maxLogEvents]logEvent
	eventCount := 0
	for _, suffix := range []string{".2", ".1", ""} {
		path := logPath + suffix
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxLogReadBytes {
			return result, errors.New("日志不是普通文件或超过 4 MiB 上限")
		}
		file, err := os.Open(path)
		if err != nil {
			return result, errors.New("日志无法打开")
		}
		opened, statErr := file.Stat()
		if statErr != nil || !os.SameFile(info, opened) {
			file.Close()
			return result, errors.New("日志在读取时被替换")
		}
		limited := &io.LimitedReader{R: file, N: maxLogReadBytes + 1}
		scanner := bufio.NewScanner(limited)
		scanner.Buffer(make([]byte, 4096), 8192)
		for scanner.Scan() {
			event, ok := parseLogEvent(scanner.Text())
			if !ok {
				continue
			}
			if event.Kind == "service_started" {
				pid = event.PID
			}
			event.PID = pid
			recent[eventCount%maxLogEvents] = event
			eventCount++
		}
		closeErr := file.Close()
		result.BytesScanned += maxLogReadBytes + 1 - limited.N
		if scanner.Err() != nil || closeErr != nil || limited.N == 0 {
			return result, errors.New("日志读取失败、单行超过 8 KiB 或读取超过 4 MiB")
		}
		result.FilesScanned++
	}
	result.EventsOmitted = max(0, eventCount-maxLogEvents)
	for i := result.EventsOmitted; i < eventCount; i++ {
		result.Events = append(result.Events, recent[i%maxLogEvents])
	}
	return result, nil
}
