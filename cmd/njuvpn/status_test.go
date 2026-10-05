package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/ipc"
)

// 验证实际进程退出码及两条输出流，不能仅测 cmdStatus 的返回值。
func TestStatusExitCodes(t *testing.T) {
	bin := testCLIBinary(t)
	for _, jsonOutput := range []bool{false, true} {
		format := "text"
		if jsonOutput {
			format = "json"
		}
		for _, tc := range []struct {
			name     string
			response *ipc.Response
			args     []string
			wantCode int
		}{
			{"ready", &ipc.Response{Code: 200, Message: `{"state":"up"}`}, nil, 0},
			{"not-ready", &ipc.Response{Code: 409, Message: `{"state":"idle"}`}, nil, 4},
			{"query-failed", &ipc.Response{Code: 500, Message: "测试查询失败"}, nil, 1},
			{"not-running", nil, nil, 3},
			{"removed-flag", nil, []string{"-check"}, 2},
			{"removed-long-flag", nil, []string{"--check"}, 2},
			{"extra-argument", nil, []string{"extra"}, 2},
			{"help", nil, []string{"-help"}, 0},
		} {
			t.Run(format+"/"+tc.name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "fixture.yaml")
				original := []byte("not a valid config; status must not read or change it")
				if err := os.WriteFile(path, original, 0600); err != nil {
					t.Fatal(err)
				}
				if tc.response != nil {
					startFakeServiceFor(t, path, func(req ipc.Request) ipc.Response {
						var wantArgs []string
						if jsonOutput {
							wantArgs = []string{"json"}
						}
						if req.Command != ipc.CmdStatus || !slices.Equal(req.Args, wantArgs) {
							t.Error("状态查询发送了额外命令或参数", req)
						}
						return *tc.response
					})
				}
				args := []string{"status", "-config", path}
				if jsonOutput {
					args = append(args, "-json")
				}
				args = append(args, tc.args...)
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, bin, args...)
				var stdout, stderr bytes.Buffer
				cmd.Stdout, cmd.Stderr = &stdout, &stderr
				err := cmd.Run()
				code := 0
				if err != nil {
					var exited *exec.ExitError
					if !errors.As(err, &exited) {
						t.Fatal("执行候选程序失败", err)
					}
					code = exited.ExitCode()
				}
				if ctx.Err() != nil || code != tc.wantCode {
					t.Fatalf("退出码=%d，期望 %d；stdout=%q stderr=%q", code, tc.wantCode, stdout.String(), stderr.String())
				}
				if tc.response != nil && strings.TrimSpace(stdout.String()) != tc.response.Message {
					t.Fatal("状态响应未完整输出", stdout.String())
				}
				if (tc.wantCode == 0 && tc.response != nil || tc.wantCode == 4) && stderr.Len() != 0 {
					t.Fatal("正常状态查询结果被额外报错", stderr.String())
				}
				if body, err := os.ReadFile(path); err != nil || !bytes.Equal(body, original) {
					t.Fatal("状态查询改动了配置", err)
				}
			})
		}
	}
}
