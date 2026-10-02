package service

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestIPCConnectionLimitAndShutdownWakeIdleClients(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(nil, ln)
	done := make(chan error, 1)
	go func() { done <- server.Serve() }()
	var clients []net.Conn
	defer func() {
		for _, c := range clients {
			c.Close()
		}
		server.Shutdown()
		server.Wait(time.Second)
	}()
	for range maxConnections {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, c)
	}
	deadline := time.After(2 * time.Second)
	for {
		server.mu.Lock()
		n := len(server.connections)
		server.mu.Unlock()
		if n == maxConnections {
			break
		}
		select {
		case <-deadline:
			t.Fatal("没有接入声明容量的连接")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	extra, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	extra.SetReadDeadline(time.Now().Add(time.Second))
	var buf [1]byte
	if _, err := extra.Read(buf[:]); err != io.EOF {
		t.Fatal("超限连接未立即拒绝", err)
	}
	server.Shutdown()
	server.Wait(time.Second)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	n := len(server.connections)
	server.mu.Unlock()
	if n != 0 {
		t.Fatal("停止未唤醒并等待空闲连接", n)
	}
}
