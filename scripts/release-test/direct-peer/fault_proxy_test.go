package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/dial"
)

func echoFaultProxy(t *testing.T) (*faultProxy, dial.DialFunc) {
	t.Helper()
	var handlers sync.WaitGroup
	proxy, err := newFaultProxy(context.Background(), func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "192.0.2.1:443" {
			t.Error("意外目标")
			return nil, errFaultCheck
		}
		client, server := net.Pipe()
		handlers.Add(1)
		go func() { defer handlers.Done(); defer server.Close(); io.Copy(server, server) }()
		return client, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { proxy.close(); handlers.Wait() })
	connect, err := dial.New(proxy.address())
	if err != nil {
		t.Fatal(err)
	}
	return proxy, connect
}

func echoCheck(t *testing.T, c net.Conn, body string) {
	t.Helper()
	c.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.WriteString(c, body); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(body))
	if _, err := io.ReadFull(c, reply); err != nil || string(reply) != body {
		t.Fatal("回环转发内容错误", err)
	}
}

func TestFaultProxyCutRejectRestoreAndClose(t *testing.T) {
	proxy, connect := echoFaultProxy(t)
	c, err := connect(context.Background(), "tcp", "192.0.2.1:443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	echoCheck(t, c, "before")
	if proxy.cut(true) != 2 {
		t.Fatal("没有同时关闭两端连接")
	}
	c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("故障后旧连接仍可读")
	}
	if next, err := connect(context.Background(), "tcp", "192.0.2.1:443"); err == nil {
		next.Close()
		t.Fatal("拒绝期连接未被拒绝")
	}
	proxy.restore()
	next, err := connect(context.Background(), "tcp", "192.0.2.1:443")
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	echoCheck(t, next, "after")
	accepted, refused, _ := proxy.counts()
	if accepted != 2 || refused != 1 {
		t.Fatalf("计数错误: %d/%d", accepted, refused)
	}
	proxy.close()
	next.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := next.Read(make([]byte, 1)); err == nil {
		t.Fatal("代理退出后连接未回收")
	}
}

func TestFaultProxySilentConsumesBytesWithoutForwarding(t *testing.T) {
	proxy, connect := echoFaultProxy(t)
	c, err := connect(context.Background(), "tcp", "192.0.2.1:443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	echoCheck(t, c, "before")
	proxy.setSilent(true)
	if _, err := io.WriteString(c, "discard"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		_, _, count := proxy.counts()
		if count == 7 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("静默注入没有实际丢弃字节")
		}
		time.Sleep(time.Millisecond)
	}
	c.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("静默期间收到转发字节")
	}
	proxy.setSilent(false)
	echoCheck(t, c, "after")
}

func TestFaultProxyRejectsOversizedAndInvalidHeadersBeforeDial(t *testing.T) {
	proxy, connect := echoFaultProxy(t)
	_ = connect
	for _, request := range []string{
		"GET / HTTP/1.1\r\nHost: 192.0.2.1:443\r\n\r\n",
		"CONNECT 192.0.2.1:443 HTTP/1.1\r\nHost: 192.0.2.1:443\r\nX-Large: " + strings.Repeat("x", 8192) + "\r\n\r\n",
		"CONNECT 192.0.2.1:443 HTTP/1.1\r\nHost: 192.0.2.1:443\r\nContent-Length: 1\r\n\r\nx",
	} {
		c, err := net.Dial("tcp", proxy.listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(time.Second))
		io.WriteString(c, request)
		if n, _ := c.Read(make([]byte, 128)); n != 0 {
			t.Fatal("非法 CONNECT 得到成功响应")
		}
		c.Close()
	}
	accepted, _, _ := proxy.counts()
	if accepted != 0 {
		t.Fatal("非法请求调用了上游")
	}
}

func TestFaultProxyCancellationWaitsForPendingDial(t *testing.T) {
	entered, finished := make(chan struct{}), make(chan struct{})
	proxy, err := newFaultProxy(context.Background(), func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(entered)
		<-ctx.Done()
		close(finished)
		return nil, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	connect, _ := dial.New(proxy.address())
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, _ := connect(context.Background(), "tcp", "192.0.2.1:443")
		if c != nil {
			c.Close()
		}
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("拨号未开始")
	}
	closed := make(chan struct{})
	go func() { proxy.close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("代理没有等待并取消拨号")
	}
	select {
	case <-finished:
	default:
		t.Fatal("代理退出后还有拨号任务")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("客户端未收尾")
	}
}

func TestPrivateCommandLogHasSharedByteBudget(t *testing.T) {
	var output bytes.Buffer
	log := &cappedLog{writer: &output, remaining: 64}
	var writers sync.WaitGroup
	for i := 0; i < 8; i++ {
		writers.Add(1)
		go func() {
			defer writers.Done()
			n, err := log.Write(bytes.Repeat([]byte{'x'}, 32))
			if n != 32 || err != nil {
				t.Error("丢弃超额日志不应改变子进程写结果")
			}
		}()
	}
	writers.Wait()
	if output.Len() != 64 {
		t.Fatalf("并发日志超出预算: %d", output.Len())
	}
}

func TestFaultProxyConnectionLimitClosesExtraClient(t *testing.T) {
	proxy, _ := echoFaultProxy(t)
	clients := make([]net.Conn, 0, 32)
	defer func() {
		for _, c := range clients {
			c.Close()
		}
	}()
	for i := 0; i < 32; i++ {
		c, err := net.Dial("tcp", proxy.listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, c)
	}
	deadline := time.Now().Add(time.Second)
	for {
		proxy.mu.Lock()
		n := len(proxy.clients)
		proxy.mu.Unlock()
		if n == 32 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("未建立满额等待连接")
		}
		time.Sleep(time.Millisecond)
	}
	extra, err := net.Dial("tcp", proxy.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	extra.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := extra.Read(make([]byte, 1)); err == nil {
		t.Fatal("超过上限的连接没有关闭")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("超额连接仍在等待请求头")
	}
	proxy.close()
	proxy.mu.Lock()
	remaining := len(proxy.clients)
	proxy.mu.Unlock()
	if remaining != 0 {
		t.Fatal("关闭没有等待已接收连接")
	}
}
