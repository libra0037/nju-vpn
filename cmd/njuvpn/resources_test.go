package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/libra0037/nju-vpn/internal/ipc"
)

func TestResourcesCommandOnlyReadsSnapshotFromExistingInstance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.yaml")
	original := []byte("this is deliberately not a valid config")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	const rule = `{"protocol":"tcp","prefix":"192.0.2.1/32","ports":[443,443]}`
	body := `{"ip":[` + strings.TrimSuffix(strings.Repeat(rule+",", 512), ",") + `],"tcpDomains":[],"dns":{"primary":"192.0.2.53","secondary":"192.0.2.54"}}`
	if len(body)+len("200 \n") > ipc.MaxLineBytes {
		t.Fatal("归一化样例超过统一响应预算")
	}
	startFakeServiceFor(t, path, func(req ipc.Request) ipc.Response {
		if req.Command != ipc.CmdResources || len(req.Args) != 0 {
			t.Error("资源命令做了额外操作", req.Command)
		}
		calls.Add(1)
		return ipc.Response{Code: 200, Message: body}
	})
	outFile, err := os.CreateTemp(t.TempDir(), "stdout-*")
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	t.Cleanup(func() { os.Stdout = old; outFile.Close() })
	os.Stdout = outFile
	err = cmdResources([]string{"-config", path})
	os.Stdout = old
	if closeErr := outFile.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.ReadFile(outFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || bytes.Count(out, []byte("\n")) != 518 || !bytes.Contains(out, []byte("192.0.2.1/32")) || !bytes.Contains(out, []byte("192.0.2.53")) {
		t.Fatal("没有只读查询并完整打印", calls.Load(), bytes.Count(out, []byte("\n")))
	}
	data, _ := os.ReadFile(path)
	if !bytes.Equal(data, original) {
		t.Fatal("修改了配置")
	}
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	if err := cmdResources([]string{"-config", missing}); !errors.Is(err, ipc.ErrNotRunning) {
		t.Fatal("无实例时启动了进程或读取配置", err)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("创建了配置")
	}
}
func TestResourceOutputUsesPublishedOrderWithoutMutation(t *testing.T) {
	resources := ipc.Resources{
		IP: []ipc.IPResource{
			{Prefix: netip.MustParsePrefix("192.0.2.1/32"), Protocol: "udp", Ports: [2]uint16{53, 53}},
			{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Protocol: "all", Ports: [2]uint16{8000, 8100}},
		},
		DNS:        ipc.ResourceDNS{Primary: "192.0.2.53", Secondary: "192.0.2.54"},
		TCPDomains: []ipc.TCPDomainResource{},
	}
	before, err := json.Marshal(resources)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := printResources(&out, resources); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != 8 || lines[0] != "IPv4 资源表" ||
		!slices.Equal(strings.Fields(lines[1]), []string{"udp", "192.0.2.1/32", "53"}) ||
		!slices.Equal(strings.Fields(lines[2]), []string{"all", "198.51.100.0/24", "8000-8100"}) ||
		lines[6] != "DNS 服务器" || lines[7] != "首选  192.0.2.53  备选  192.0.2.54" || strings.ContainsRune(out.String(), '\x1b') {
		t.Fatal("打印顺序、格式或字段错误", out.String())
	}
	after, _ := json.Marshal(resources)
	if !bytes.Equal(before, after) {
		t.Fatal("打印修改了发布状态")
	}
	var empty bytes.Buffer
	if err := printResources(&empty, ipc.Resources{IP: []ipc.IPResource{}, TCPDomains: []ipc.TCPDomainResource{}}); err != nil || !strings.Contains(empty.String(), "IPv4 资源表为空") || !strings.Contains(empty.String(), "DNS 服务器") {
		t.Fatal("空规则列表未保留 DNS 展示", empty.String(), err)
	}
}

func TestResourceOutputRejectsInvalidIPCFieldsBeforePrinting(t *testing.T) {
	for i, resource := range []ipc.Resources{
		{IP: []ipc.IPResource{{Prefix: netip.MustParsePrefix("::/0"), Protocol: "all", Ports: [2]uint16{1, 65535}}}},
		{IP: []ipc.IPResource{{Prefix: netip.MustParsePrefix("192.0.2.1/24"), Protocol: "tcp", Ports: [2]uint16{443, 443}}}},
		{IP: []ipc.IPResource{{Prefix: netip.MustParsePrefix("192.0.2.1/32"), Protocol: "unknown", Ports: [2]uint16{443, 443}}}},
		{IP: []ipc.IPResource{{Prefix: netip.MustParsePrefix("192.0.2.1/32"), Protocol: "tcp", Ports: [2]uint16{443, 80}}}},
		{DNS: ipc.ResourceDNS{Primary: "192.0.2.53\n\x1b[2J"}},
	} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			var out bytes.Buffer
			if err := printResources(&out, resource); err == nil || out.Len() != 0 {
				t.Fatal("非法响应仍有输出", out.String(), err)
			}
		})
	}
}

func TestRestartRejectsFailureBeforeAnyStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unreadable.yaml")
	var calls atomic.Int32
	startFakeServiceFor(t, path, func(req ipc.Request) ipc.Response {
		calls.Add(1)
		if req.Command != ipc.CmdShutdown {
			t.Error("shutdown 失败后继续操作", req.Command)
		}
		return ipc.Response{Code: 500, Message: "failed"}
	})
	if err := cmdRestart([]string{"-config", path}); err == nil {
		t.Fatal("shutdown 失败仍报告成功")
	}
	if calls.Load() != 1 {
		t.Fatal("失败后继续操作", calls.Load())
	}
}
func TestCLIFlagClassification(t *testing.T) {
	fs := flag.NewFlagSet("resources", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var ue *usageError
	if err := parseNoPositional(fs, []string{"-invalid"}); !errors.As(err, &ue) {
		t.Fatal("选项错误未返回用法类别", err)
	}
	if err := parseNoPositional(fs, []string{"-help"}); !errors.Is(err, flag.ErrHelp) {
		t.Fatal("帮助未返回成功类别", err)
	}
}
func TestLogRotationTotalBudget(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "daemon.log")
	l, err := openRotatingLog(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	p := bytes.Repeat([]byte("a"), maxLogBytes)
	for range 5 {
		if n, err := l.Write(p); err != nil || n != len(p) {
			t.Fatal(n, err)
		}
	}
	for _, name := range []string{path, path + ".1", path + ".2"} {
		info, err := os.Stat(name)
		if err != nil || info.Size() > maxLogBytes {
			t.Fatal("日志超过预算", err)
		}
	}
	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Fatal("多出日志备份")
	}
	if _, err := l.Write(make([]byte, maxLogBytes+1)); err == nil {
		t.Fatal("单条超预算记录未拒绝")
	}
}

func TestStdinLineBudget(t *testing.T) {
	setStdin(t, strings.Repeat("x", 8192))
	if _, err := readStdinLine(); err == nil {
		t.Fatal("超限输入未拒绝")
	}
	setStdin(t, strings.Repeat("x", 8191), "next")
	if s, err := readStdinLine(); err != nil || len(s) != 8191 {
		t.Fatal("合法行被拒绝", err)
	}
	if s, err := readStdinLine(); err != nil || s != "next" {
		t.Fatal("预读的下一行丢失", err)
	}
}
