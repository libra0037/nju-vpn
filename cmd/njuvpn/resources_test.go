package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/libra0037/nju-vpn/internal/ipc"
	"github.com/libra0037/nju-vpn/internal/ztna"
)

func TestResourcesCommandOnlyReadsSnapshotFromExistingInstance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.yaml")
	original := []byte("this is deliberately not a valid config")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	const app = `{"id":"app","accessModel":"","nodeGroupId":"g","addressList":[{"host":"192.0.2.1","protocol":"tcp","port":"443","ip":null}]}`
	body := "[" + strings.TrimSuffix(strings.Repeat(app+",", 600), ",") + "]"
	if len(body)+len("200 \n") <= ipc.MaxLineBytes {
		t.Fatal("样例没有超过普通响应预算")
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
	if calls.Load() != 1 || bytes.Count(out, []byte("\n")) != 601 || !bytes.Contains(out, []byte("app")) {
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
func TestResourceOutputIsDeterministicAndEscapesTerminalText(t *testing.T) {
	list := []ztna.Resource{
		{ID: "z", AccessModel: "L3VPN", AddressList: []ztna.ResourceAddress{{Host: "domain", Protocol: "odd", Port: "1", IP: []string{"10.2.1.1", "10.1.1.1"}}}},
		{ID: "a\x1b[2J\n", NodeGroupID: "g", AddressList: []ztna.ResourceAddress{}},
	}
	raw, _ := json.Marshal(list)
	var a, b bytes.Buffer
	if err := printResources(&a, list); err != nil {
		t.Fatal(err)
	}
	var again []ztna.Resource
	json.Unmarshal(raw, &again)
	again[0], again[1] = again[1], again[0]
	if err := printResources(&b, again); err != nil {
		t.Fatal(err)
	}
	if a.String() != b.String() || strings.ContainsRune(a.String(), '\x1b') || !strings.Contains(a.String(), `\x1b`) || bytes.Count(a.Bytes(), []byte("\n")) != 3 {
		t.Fatal("排序不稳定或未转义", a.String(), b.String())
	}
	var empty bytes.Buffer
	printResources(&empty, []ztna.Resource{})
	if !strings.Contains(empty.String(), "为空") {
		t.Fatal("有效空列表未打印")
	}
}

func TestResourceOrderingDoesNotDependOnSeparatorCharacters(t *testing.T) {
	addresses := []ztna.ResourceAddress{{Host: "x\x00y", Protocol: "z"}, {Host: "x", Protocol: "y\x00z"}}
	first := []ztna.Resource{{ID: "a", AddressList: addresses}}
	second := []ztna.Resource{{ID: "a", AddressList: []ztna.ResourceAddress{addresses[1], addresses[0]}}}
	var a, b bytes.Buffer
	printResources(&a, first)
	printResources(&b, second)
	if a.String() != b.String() {
		t.Fatal("字段内的分隔字符影响稳定排序")
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
