package main

import (
	"bufio"
	"net"
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
