package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClientRejectsWrongOrMissingIdentityBeforeSendingSecrets(t *testing.T) {
	for _, tc := range []struct {
		name, message string
		code          int
	}{
		{"different-config", `{"config":"/private/other-config.yaml"}`, 200},
		{"empty-config", `{"config":""}`, 200},
		{"missing-config", `{}`, 200},
		{"old-pong", "pong old-instance", 200},
		{"malformed", `{"config":`, 200},
		{"failed", `{"config":"/private/other-config.yaml"}`, 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := NewClient(filepath.Join(t.TempDir(), "config.yaml"))
			ln, err := Listen(client.endpoint)
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
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				reader := bufio.NewReader(conn)
				first, err := ReadRequest(reader)
				if err != nil || first.Command != "ping" || len(first.Args) != 0 {
					done <- errors.New("身份核验之前发送了操作或凭据")
					return
				}
				if err := WriteResponse(conn, Response{Code: tc.code, Message: tc.message}); err != nil {
					done <- err
					return
				}
				_, err = ReadRequest(reader)
				if !errors.Is(err, io.EOF) {
					done <- errors.New("错误实例收到身份核验之外的请求，或连接未关闭")
					return
				}
				done <- nil
			}()
			_, err = client.Call(Request{Command: CmdStart, Args: []string{"trust=1", EncodeSecret("test-secret")}}, time.Second)
			if !errors.Is(err, ErrInstanceMismatch) || strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "test-secret") {
				t.Fatal("错误实例没有被有限类别拒绝", err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestClientCancellationClosesIdentityAndOperationWaits(t *testing.T) {
	for _, phase := range []string{"identity", "operation"} {
		t.Run(phase, func(t *testing.T) {
			client := NewClient(filepath.Join(t.TempDir(), "config.yaml"))
			listener, err := Listen(client.endpoint)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { listener.Close() })
			ready := make(chan error, 1)
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					ready <- err
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				reader := bufio.NewReader(conn)
				request, err := ReadRequest(reader)
				if err != nil || request.Command != CmdPing {
					ready <- errors.New("没有先读取身份")
					return
				}
				if phase == "operation" {
					body, _ := json.Marshal(InstanceIdentity{ConfigPath: client.identity})
					if err := WriteResponse(conn, Response{Code: CodeOK, Message: string(body)}); err != nil {
						ready <- err
						return
					}
					request, err = ReadRequest(reader)
					if err != nil || request.Command != CmdState {
						ready <- errors.New("身份核验后没有发送操作")
						return
					}
				}
				ready <- nil
				_, err = ReadRequest(reader)
				if !errors.Is(err, io.EOF) {
					done <- errors.New("取消后连接未关闭，或继续发送请求")
					return
				}
				done <- nil
			}()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				_, err := client.CallContext(ctx, Request{Command: CmdState}, 5*time.Second)
				result <- err
			}()
			if err := <-ready; err != nil {
				t.Fatal(err)
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("取消没有保留稳定类别", err)
				}
			case <-time.After(time.Second):
				t.Fatal("取消后仍等待原请求期限")
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestClientChecksEachCallOnTheSameConnection(t *testing.T) {
	client := NewClient(filepath.Join(t.TempDir(), "config.yaml"))
	ln, err := Listen(client.endpoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	body, err := json.Marshal(InstanceIdentity{ConfigPath: client.identity})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		for attempt := range 2 {
			conn, err := ln.Accept()
			if err != nil {
				done <- err
				return
			}
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			reader := bufio.NewReader(conn)
			first, err := ReadRequest(reader)
			if err != nil || first.Command != "ping" {
				conn.Close()
				done <- errors.New("调用没有重新核验身份")
				return
			}
			identity := string(body)
			if attempt == 1 {
				identity = `{"config":"other-config.yaml"}`
			}
			if err := WriteResponse(conn, Response{Code: CodeOK, Message: identity}); err != nil {
				conn.Close()
				done <- err
				return
			}
			request, err := ReadRequest(reader)
			if attempt == 1 {
				conn.Close()
				if !errors.Is(err, io.EOF) {
					done <- errors.New("缓存了前一次核验，操作被发给更换后的实例")
					return
				}
			} else {
				if err != nil || request.Command != "stop" {
					conn.Close()
					done <- errors.New("核验和操作没有使用同一连接")
					return
				}
				if err := WriteResponse(conn, Response{Code: CodeOK, Message: "stopped"}); err != nil {
					conn.Close()
					done <- err
					return
				}
				conn.Close()
			}
		}
		done <- nil
	}()
	response, err := client.Call(Request{Command: CmdStop}, time.Second)
	if err != nil || response != (Response{Code: CodeOK, Message: "stopped"}) {
		t.Fatal("合法实例操作失败", response, err)
	}
	if _, err := client.Call(Request{Command: CmdShutdown}, time.Second); !errors.Is(err, ErrInstanceMismatch) {
		t.Fatal("更换实例后仍通过核验", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestClientZeroValueIsRejected(t *testing.T) {
	for _, client := range []*Client{nil, {}} {
		if _, err := client.Call(Request{Command: CmdPing}, time.Second); !errors.Is(err, ErrEmptyEndpoint) {
			t.Fatal("不可用的客户端没有被拒绝", err)
		}
	}
}
