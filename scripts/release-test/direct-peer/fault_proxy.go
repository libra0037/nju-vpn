package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/libra0037/nju-vpn/internal/dial"
)

// 只用于独立测试实例的回环 CONNECT 转发。上游沿用原配置的出站方式。
// 最多 32 条连接、8 KiB 请求头、每方向 32 KiB 缓冲；不记录目的地址或字节内容。
type faultProxy struct {
	listener  net.Listener
	dial      dial.DialFunc
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	mu        sync.Mutex
	clients   map[net.Conn]net.Conn
	reject    bool
	silent    bool
	accepted  int
	refused   int
	discarded int64
}

func newFaultProxy(parent context.Context, dialer dial.DialFunc) (*faultProxy, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	p := &faultProxy{listener: listener, dial: dialer, ctx: ctx, cancel: cancel, clients: make(map[net.Conn]net.Conn)}
	p.wg.Add(1)
	go p.accept()
	return p, nil
}

func (p *faultProxy) address() string { return "http://" + p.listener.Addr().String() }

func (p *faultProxy) accept() {
	defer p.wg.Done()
	for {
		client, err := p.listener.Accept()
		if err != nil {
			return
		}
		p.mu.Lock()
		if p.ctx.Err() != nil || len(p.clients) >= 32 {
			p.mu.Unlock()
			client.Close()
			continue
		}
		p.clients[client] = nil
		p.wg.Add(1)
		p.mu.Unlock()
		go p.serve(client)
	}
}

func (p *faultProxy) serve(client net.Conn) {
	defer p.wg.Done()
	var upstream net.Conn
	defer func() {
		client.Close()
		if upstream != nil {
			upstream.Close()
		}
		p.mu.Lock()
		delete(p.clients, client)
		p.mu.Unlock()
	}()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	// njuvpn 先等待 CONNECT 200 才发送 TLS，禁止预发送数据以免丢掉缓冲。
	limited := &io.LimitedReader{R: client, N: 8193}
	reader := bufio.NewReader(limited)
	req, err := http.ReadRequest(reader)
	if err != nil || limited.N == 0 || req.Method != "CONNECT" || req.ContentLength > 0 || len(req.TransferEncoding) != 0 || reader.Buffered() != 0 || !dial.ValidHostPort(req.Host) {
		return
	}
	p.mu.Lock()
	blocked := p.reject
	if blocked {
		p.refused++
	}
	p.mu.Unlock()
	if blocked {
		io.WriteString(client, "HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n")
		return
	}
	ctx, cancel := context.WithTimeout(p.ctx, 20*time.Second)
	defer cancel()
	upstream, err = p.dial(ctx, "tcp", req.Host)
	if err != nil {
		io.WriteString(client, "HTTP/1.1 502 Failed\r\nContent-Length: 0\r\n\r\n")
		return
	}
	p.mu.Lock()
	if p.reject || p.ctx.Err() != nil {
		p.mu.Unlock()
		return
	}
	p.clients[client] = upstream
	p.accepted++
	p.mu.Unlock()
	if _, err := io.WriteString(client, "HTTP/1.1 200 Established\r\n\r\n"); err != nil {
		return
	}
	client.SetDeadline(time.Time{})
	done := make(chan struct{})
	go func() { defer close(done); p.copy(upstream, client); upstream.Close(); client.Close() }()
	p.copy(client, upstream)
	upstream.Close()
	client.Close()
	<-done
}

func (p *faultProxy) copy(dst, src net.Conn) {
	buffer := make([]byte, 32768)
	for {
		n, err := src.Read(buffer)
		if n > 0 {
			p.mu.Lock()
			silent := p.silent
			if silent {
				p.discarded += int64(n)
			}
			p.mu.Unlock()
			if !silent {
				if written, writeErr := dst.Write(buffer[:n]); writeErr != nil || written != n {
					return
				}
			}
		}
		if err != nil {
			return
		}
	}
}

func (p *faultProxy) setSilent(silent bool) {
	p.mu.Lock()
	p.silent = silent
	p.mu.Unlock()
}

func (p *faultProxy) cut(reject bool) int {
	p.mu.Lock()
	p.reject = reject
	connections := make([]net.Conn, 0, len(p.clients)*2)
	for client, upstream := range p.clients {
		connections = append(connections, client)
		if upstream != nil {
			connections = append(connections, upstream)
		}
	}
	p.mu.Unlock()
	for _, connection := range connections {
		connection.Close()
	}
	return len(connections)
}

func (p *faultProxy) restore() {
	p.mu.Lock()
	p.reject, p.silent = false, false
	p.mu.Unlock()
}

func (p *faultProxy) counts() (accepted, refused int, discarded int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.accepted, p.refused, p.discarded
}

func (p *faultProxy) close() {
	p.cancel()
	p.listener.Close()
	p.cut(true)
	p.wg.Wait()
}

var errFaultCheck = errors.New("故障注入或恢复判据未满足")
