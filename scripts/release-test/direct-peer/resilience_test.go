package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/ipc"
)

func TestResilienceRejectsWrongInstanceBeforeSendingOperation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	listener, err := ipc.Listen(ipc.EndpointFor(path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(time.Second))
		reader := bufio.NewReader(conn)
		request, err := ipc.ReadRequest(reader)
		if err != nil || request.Command != ipc.CmdPing || len(request.Args) != 0 {
			done <- errors.New("身份核验之前发送了操作或凭据")
			ipc.WriteResponse(conn, ipc.Response{Code: ipc.CodeOK, Message: "wrong-instance"})
			return
		}
		if err := ipc.WriteResponse(conn, ipc.Response{Code: ipc.CodeOK, Message: `{"config":"/other/config.yaml"}`}); err != nil {
			done <- err
			return
		}
		_, err = ipc.ReadRequest(reader)
		if !errors.Is(err, io.EOF) {
			done <- errors.New("错误实例收到操作，或连接没有关闭")
			return
		}
		done <- nil
	}()
	_, callErr := ipcCall(context.Background(), path, ipc.CmdStart, []string{"trust=0", ipc.EncodeSecret("test-secret")}, time.Second)
	serverErr := <-done
	if !errors.Is(callErr, ipc.ErrInstanceMismatch) || serverErr != nil {
		t.Fatal("故障测试工具没有核验配置身份", callErr, serverErr)
	}
}
