package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/ipc"
)

func TestManagementCommandsRejectWrongConfigInstance(t *testing.T) {
	bin := testCLIBinary(t)
	for _, args := range [][]string{
		{"start"}, {"stop"}, {"status"}, {"resources"}, {"restart"}, {"trust"}, {"untrust", "--all"}, {"start", "--endpoint", "socks5"},
	} {
		t.Run(strings.Join(args, "-"), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			body := []byte("server: vpn.test\nusername: test-user\npassword: test-secret\npinned_node_spki_sha256: [AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=]\nsocks5:\n  enabled: true\n")
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			ln, err := ipc.Listen(ipc.EndpointFor(path))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { ln.Close() })
			done := make(chan error, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				reader := bufio.NewReader(conn)
				request, err := ipc.ReadRequest(reader)
				if err != nil || request.Command != "ping" || len(request.Args) != 0 {
					done <- errors.New("错误实例在核验前收到管理操作或凭据")
					return
				}
				if err := ipc.WriteResponse(conn, ipc.Response{Code: 200, Message: `{"config":"other-instance.yaml"}`}); err != nil {
					done <- err
					return
				}
				if _, err := ipc.ReadRequest(reader); !errors.Is(err, io.EOF) {
					done <- errors.New("错误实例在核验失败后仍收到请求")
					return
				}
				done <- nil
			}()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			commandArgs := append(append([]string(nil), args...), "--config", path)
			cmd := exec.CommandContext(ctx, bin, commandArgs...)
			output, err := cmd.CombinedOutput()
			var exited *exec.ExitError
			if ctx.Err() != nil || !errors.As(err, &exited) || exited.ExitCode() != 1 || !strings.Contains(string(output), ipc.ErrInstanceMismatch.Error()) {
				t.Fatalf("管理入口未拒绝错误实例：%v\n%s", err, output)
			}
			if strings.Contains(string(output), "test-secret") || strings.Contains(string(output), "other-instance") {
				t.Fatal("核验错误泄露凭据或对端身份")
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if after, err := os.ReadFile(path); err != nil || string(after) != string(body) {
				t.Fatal("错误实例核验修改了配置", err)
			}
		})
	}
}

func TestLogFileNameFitsWithLongInstanceAndRotationSuffix(t *testing.T) {
	a := filepath.Join(t.TempDir(), strings.Repeat("a", 240)+".yaml")
	b := filepath.Join(filepath.Dir(a), strings.Repeat("a", 239)+"b.yaml")
	first, second := logFileName(a), logFileName(b)
	if len(first+".2") > 255 || len(second+".2") > 255 || first == second {
		t.Fatal("加长身份后的日志文件名超限，或截断后混淆实例")
	}
}
