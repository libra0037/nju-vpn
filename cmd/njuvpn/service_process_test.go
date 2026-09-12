package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/ipc"
)

// fakeService 起一个只会 pong、并且记录 shutdown 的假服务端。
func fakeService(t *testing.T) (endpoint string, gotShutdown chan struct{}) {
	t.Helper()
	endpoint = filepath.Join(t.TempDir(), "njuvpn.sock")
	ln, err := ipc.Listen(endpoint)
	if err != nil {
		t.Fatalf("监听假服务端: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	gotShutdown = make(chan struct{}, 1)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				for {
					req, err := ipc.ReadRequest(reader)
					if err != nil {
						return
					}
					switch req.Command {
					case ipc.CmdPing:
						_ = ipc.WriteResponse(conn, ipc.Response{Code: ipc.CodeOK, Message: "pong"})
					case ipc.CmdShutdown:
						_ = ipc.WriteResponse(conn, ipc.Response{Code: ipc.CodeOK, Message: "服务进程正在退出"})
						select {
						case gotShutdown <- struct{}{}:
						default:
						}
						return
					default:
						_ = ipc.WriteResponse(conn, ipc.Response{Code: ipc.CodeBadRequest, Message: "未知命令"})
					}
				}
			}(conn)
		}
	}()
	return endpoint, gotShutdown
}

// TestWaitServiceReadyReturnsOnExit 验证子进程提前退出时立刻报错。
//
// 以前这里只轮询端点：子进程因为配置写错之类立刻退出时，用户要干等满
// 超时，再被指去翻日志——而原因其实已经写在那里了（REVIEW R5 / M3）。
func TestWaitServiceReadyReturnsOnExit(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "njuvpn-test.log")
	body := "配置有问题\n服务进程崩溃前的最后一句\n"
	if err := os.WriteFile(logPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	exited <- errors.New("exit status 1")

	start := time.Now()
	err := waitServiceReady(filepath.Join(t.TempDir(), "nobody.sock"), logPath, exited, 5*time.Second)
	if err == nil {
		t.Fatal("子进程退出后应当立刻报错")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("应当立刻返回，实际等了 %s", elapsed)
	}
	if !strings.Contains(err.Error(), "服务进程崩溃前的最后一句") {
		t.Fatalf("错误里应带上日志尾部，实际 %v", err)
	}
}

// TestWaitServiceReadySucceeds 验证端点开始应答时返回成功。
func TestWaitServiceReadySucceeds(t *testing.T) {
	endpoint, _ := fakeService(t)
	// 永不写入的 channel：子进程一直在跑。
	exited := make(chan error, 1)
	if err := waitServiceReady(endpoint, filepath.Join(t.TempDir(), "x.log"), exited, 5*time.Second); err != nil {
		t.Fatalf("端点在应答时应当成功: %v", err)
	}
}

// TestWaitServiceReadyTimesOut 验证超时后报错，并附上日志尾部。
func TestWaitServiceReadyTimesOut(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "njuvpn-test.log")
	if err := os.WriteFile(logPath, []byte("还在初始化\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := waitServiceReady(filepath.Join(t.TempDir(), "nobody.sock"), logPath, make(chan error), 200*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "没有就绪") {
		t.Fatalf("超时应当报错，实际 %v", err)
	}
	if !strings.Contains(err.Error(), "还在初始化") {
		t.Fatalf("错误里应带上日志尾部，实际 %v", err)
	}
}

// TestLogTail 验证只取最后几行。
func TestLogTail(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "njuvpn-test.log")
	var b strings.Builder
	b.WriteString("第一行不该出现\n")
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&b, "第 %d 行\n", i)
	}
	if err := os.WriteFile(logPath, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	tail := logTail(logPath)
	if !strings.Contains(tail, "第 39 行") {
		t.Fatalf("尾部应包含最后一行: %q", tail)
	}
	if strings.Contains(tail, "第一行不该出现") {
		t.Fatalf("尾部不该包含开头的行: %q", tail)
	}
}

// 探活成功是"服务进程在运行"的唯一判据，ensureService 靠它决定要不要拉起。
func TestPingServiceTalksToEndpoint(t *testing.T) {
	endpoint, _ := fakeService(t)
	if err := pingService(endpoint); err != nil {
		t.Fatalf("探活失败: %v", err)
	}
}

func TestShutdownServiceSendsCommand(t *testing.T) {
	endpoint, got := fakeService(t)
	if err := shutdownService(endpoint); err != nil {
		t.Fatalf("shutdown 失败: %v", err)
	}
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("假服务端没有收到 shutdown 命令")
	}
}

// 没有服务进程时探活必须立刻失败而不是挂住。
func TestPingServiceFailsWhenNothingListens(t *testing.T) {
	endpoint := filepath.Join(t.TempDir(), "nobody.sock")
	done := make(chan error, 1)
	go func() { done <- pingService(endpoint) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("没有服务进程时探活应失败")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("探活挂住了")
	}
}

// 日志落在配置文件旁边：（被拉起的）服务进程没有控制台，出问题要看它。
func TestServiceLogPathNextToConfig(t *testing.T) {
	dir := t.TempDir()
	got := serviceLogPath(filepath.Join(dir, "config.yaml"))
	if want := filepath.Join(dir, "njuvpn-config.log"); got != want {
		t.Errorf("serviceLogPath = %q，想要 %q", got, want)
	}
}

// TestLogFileNameDistinguishesInstances 验证同目录的多份配置不共用日志。
//
// 多实例的日志交错在一份文件里，排查时最先要回答的"这一行是谁写的"
// 就没法回答了。
func TestLogFileNameDistinguishesInstances(t *testing.T) {
	alice := logFileName(filepath.Join("etc", "njuvpn", "alice.yaml"))
	bob := logFileName(filepath.Join("etc", "njuvpn", "bob.yaml"))
	if alice == bob {
		t.Fatalf("两份配置得到同一个日志名: %q", alice)
	}
	if want := "njuvpn-alice.log"; alice != want {
		t.Errorf("logFileName = %q，想要 %q", alice, want)
	}
	// 路径分隔符之类的东西不该进文件名。
	if got := logFileName("weird/../x:y.yaml"); strings.ContainsAny(got, "/:\\") {
		t.Errorf("日志名里带上了路径分隔符: %q", got)
	}
}
