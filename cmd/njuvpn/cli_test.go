package main

import (
	"bufio"
	"errors"
	"flag"
	"path/filepath"
	"strings"
	"testing"

	"github.com/libra0037/nju-vpn/internal/ipc"
	"github.com/libra0037/nju-vpn/internal/service"
)

const nl = "\n"

func TestParseInterleavedKeepsOrderAndFlags(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	configPath := fs.String("config", "", "配置文件路径")
	trust := fs.Bool("trust", false, "绑授信")

	positional, err := parseInterleaved(fs, []string{"a", "-config", "/tmp/x.yaml", "b", "-trust"})
	if err != nil {
		t.Fatal(err)
	}
	if *configPath != "/tmp/x.yaml" || !*trust {
		t.Errorf("flag 解析结果 = %q / %v", *configPath, *trust)
	}
	if len(positional) != 2 || positional[0] != "a" || positional[1] != "b" {
		t.Errorf("位置参数 = %v，期望 [a b]", positional)
	}

	fs2 := flag.NewFlagSet("test2", flag.ContinueOnError)
	if _, err := parseInterleaved(fs2, []string{"-nope"}); err == nil {
		t.Error("未知 flag 应报错")
	}
}

// TestCommandsRejectPositionalArgs 验证多写的位置参数会被当成用法错误。
//
// 这些命令都不接受位置参数，静默丢掉的话 `untrust all` 会降级成"只解绑本机"，
// 提示语却跟真做了全量一样——一个安全操作被悄悄降级。
func TestCommandsRejectPositionalArgs(t *testing.T) {
	cases := []struct {
		name string
		run  func([]string) error
		args []string
	}{
		{"untrust", cmdUntrust, []string{"all"}},
		{"trust", cmdTrust, []string{"self"}},
		{"status", cmdStatus, []string{"extra"}},
		{"stop", cmdStop, []string{"foo"}},
		{"start", cmdStart, []string{"extra"}},
		{"restart", cmdRestart, []string{"extra"}},
		{"run", cmdRun, []string{"extra"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.run(c.args)
			var ue *usageError
			if !errors.As(err, &ue) {
				t.Fatalf("多余的位置参数应报用法错误，得到 %v", err)
			}
			if want := c.args[0]; !strings.Contains(err.Error(), want) {
				t.Errorf("错误里应指出多写的参数 %q，得到 %q", want, err)
			}
		})
	}
}

func TestBoolArg(t *testing.T) {
	if got := boolArg("trust", true); got != "trust=1" {
		t.Errorf("true 应编成 trust=1，得到 %q", got)
	}
	if got := boolArg("all", false); got != "all=0" {
		t.Errorf("false 应编成 all=0，得到 %q", got)
	}
}

func TestLogFileNameDistinguishesInstance(t *testing.T) {
	a := logFileName("/home/a/config.yaml")
	b := logFileName("/home/b/config.yaml")
	if a == b {
		t.Errorf("不同配置应得到不同的日志名: %q", a)
	}
	if !strings.HasPrefix(a, "njuvpn-") || !strings.HasSuffix(a, "-config.log") {
		t.Errorf("日志名格式不对: %q", a)
	}
	weird := logFileName(filepath.Join("/home/a", "my config.yaml"))
	if strings.ContainsAny(weird, " /") {
		t.Errorf("日志名里不该出现路径分隔符与空格: %q", weird)
	}
}

// startFakeService 起一个只按脚本应答的"服务进程"，用来测命令行的分支。
func startFakeService(t *testing.T, handle func(ipc.Request) ipc.Response) string {
	t.Helper()
	endpoint := filepath.Join(t.TempDir(), "njuvpn-test.sock")
	ln, err := ipc.Listen(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				for {
					req, err := ipc.ReadRequest(reader)
					if err != nil {
						return
					}
					if err := ipc.WriteResponse(conn, handle(req)); err != nil {
						return
					}
				}
			}()
		}
	}()
	return endpoint
}

// setStdin 让交互提示从给定的几行文本里读，模拟用户在终端里敲。
func setStdin(t *testing.T, lines ...string) {
	t.Helper()
	stdinReader = bufio.NewReader(strings.NewReader(strings.Join(lines, nl) + nl))
	t.Cleanup(func() { stdinReader = nil })
}

func TestFinishSubmitsCodeAndRetriesAfterRejection(t *testing.T) {
	var submitted []string
	endpoint := startFakeService(t, func(req ipc.Request) ipc.Response {
		switch req.Command {
		case ipc.CmdState:
			return ipc.Response{Code: ipc.CodeOK, Message: string(service.StateAuthPending)}
		case ipc.CmdAuth:
			submitted = append(submitted, ipc.Arg(req.Args, 0))
			if len(submitted) == 1 {
				// 第一次输错：服务进程回 400，但会话还等着。
				return ipc.Response{Code: ipc.CodeBadRequest, Message: "验证码错误"}
			}
			return ipc.Response{Code: ipc.CodeOK, Message: "隧道已建立"}
		default:
			return ipc.Response{Code: ipc.CodeBadRequest, Message: "未知命令"}
		}
	})
	setStdin(t, "111111", "222222")

	resp := ipc.Response{Code: ipc.CodeAuthRequired, Message: "验证码已发送至 138****0000"}
	if err := finish(endpoint, resp); err != nil {
		t.Fatalf("finish: %v", err)
	}
	if len(submitted) != 2 || submitted[0] != "111111" || submitted[1] != "222222" {
		t.Errorf("提交的验证码 = %v，期望 [111111 222222]", submitted)
	}
}

func TestFinishStopsAfterTooManyAttempts(t *testing.T) {
	endpoint := startFakeService(t, func(req ipc.Request) ipc.Response {
		switch req.Command {
		case ipc.CmdState:
			return ipc.Response{Code: ipc.CodeOK, Message: string(service.StateAuthPending)}
		default:
			return ipc.Response{Code: ipc.CodeBadRequest, Message: "验证码错误"}
		}
	})
	setStdin(t, "1", "2", "3", "4")

	resp := ipc.Response{Code: ipc.CodeAuthRequired, Message: "验证码已发送"}
	if err := finish(endpoint, resp); err == nil {
		t.Fatal("连续输错验证码应以失败收场，不该一直问下去")
	}
}

func TestFinishReportsRejectionWithoutAskingForCode(t *testing.T) {
	asked := false
	endpoint := startFakeService(t, func(req ipc.Request) ipc.Response {
		if req.Command == ipc.CmdAuth {
			asked = true
		}
		return ipc.Response{Code: ipc.CodeOK, Message: string(service.StateError)}
	})
	setStdin(t, "111111")

	resp := ipc.Response{Code: ipc.CodeBadRequest, Message: "服务端拒绝: 口令错误"}
	err := finish(endpoint, resp)
	if err == nil {
		t.Fatal("口令错误应直接失败")
	}
	if asked {
		t.Error("还没输过验证码时不该去提交验证码")
	}
	if !strings.Contains(err.Error(), "口令错误") {
		t.Errorf("错误信息应带上服务端说明，得到 %v", err)
	}
}
