// Package socks5 提供有界的 TCP CONNECT 接入，校园登录与 L4 拨号由消费者注入。
package socks5

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libra0037/nju-vpn/internal/dial"
	"github.com/libra0037/nju-vpn/internal/ztna"
)

const (
	DefaultMaxConnections   = 128
	MaxConnections          = 4096
	DefaultMaxDials         = 32
	MaxDials                = 128
	defaultHandshakeTimeout = 10 * time.Second
	connectTimeout          = 15 * time.Second
	copyBufferBytes         = 32 * 1024
)

// Stream 由此消费者定义；BoundAddress 是校园目标连接的绑定地址。
type Stream interface {
	net.Conn
	CloseWrite() error
	BoundAddress() (string, uint16)
}
type DialFunc func(context.Context, ztna.TCPTarget) (Stream, error)

type Options struct {
	Username         string
	Password         string
	MaxConnections   int
	MaxDials         int
	HandshakeTimeout time.Duration // 测试可缩短；0 使用十秒。
}

type Diagnostics struct {
	Listening   bool   `json:"listening"`
	Port        int    `json:"port"`
	Connections int    `json:"connections"`
	Dialing     int    `json:"dialing"`
	Rejected    uint64 `json:"rejected"`
	Failed      uint64 `json:"failed"`
}

// Server 的 Run 拥有接受与转发任务；Close 取消、关闭并等待，创建不启动协程。
type Server struct {
	listener    net.Listener
	port        int
	opts        Options
	auth        bool
	username    [sha256.Size]byte
	password    [sha256.Size]byte
	dialSlots   chan struct{}
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	closed      bool
	started     bool
	cancel      context.CancelFunc
	done        chan struct{}
	ready       chan struct{}
	workers     sync.WaitGroup
	rejected    atomic.Uint64
	failed      atomic.Uint64
}

func New(address string, opts Options) (*Server, error) {
	if opts.MaxConnections < 1 || opts.MaxConnections > MaxConnections || opts.MaxDials < 1 || opts.MaxDials > MaxDials || opts.MaxDials > opts.MaxConnections {
		return nil, errors.New("SOCKS 连接或建连预算非法")
	}
	if (opts.Username == "") != (opts.Password == "") || len(opts.Username) > 255 || len(opts.Password) > 255 {
		return nil, errors.New("SOCKS 认证须同时提供 1-255 字节的用户名和口令")
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("SOCKS 监听地址非法")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Is4() {
		return nil, errors.New("SOCKS 监听地址须为 IPv4")
	}
	if !ip.IsLoopback() && opts.Username == "" {
		return nil, errors.New("SOCKS 非回环监听必须配置认证")
	}
	if opts.HandshakeTimeout == 0 {
		opts.HandshakeTimeout = defaultHandshakeTimeout
	}
	if opts.HandshakeTimeout < 0 {
		return nil, errors.New("SOCKS 握手预算须为正数")
	}
	ln, err := net.Listen("tcp4", address)
	if err != nil {
		return nil, dial.Wrap("SOCKS 监听", err)
	}
	s := &Server{listener: ln, port: ln.Addr().(*net.TCPAddr).Port, opts: opts, auth: opts.Username != "", username: sha256.Sum256([]byte(opts.Username)), password: sha256.Sum256([]byte(opts.Password)), dialSlots: make(chan struct{}, opts.MaxDials), connections: make(map[net.Conn]struct{}), done: make(chan struct{}), ready: make(chan struct{})}
	s.opts.Username, s.opts.Password = "", "" // 运行态只保留摘要。
	return s, nil
}

func (s *Server) Diagnostics() Diagnostics {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Diagnostics{Listening: !s.closed, Port: s.port, Connections: len(s.connections), Dialing: len(s.dialSlots), Rejected: s.rejected.Load(), Failed: s.failed.Load()}
}

func (s *Server) Run(parent context.Context, connect DialFunc) error {
	if connect == nil {
		return errors.New("SOCKS 缺少校园拨号实现")
	}
	s.mu.Lock()
	if s.closed || s.started {
		s.mu.Unlock()
		return errors.New("SOCKS 运行任务已结束或已启动")
	}
	s.started = true
	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	close(s.ready)
	s.mu.Unlock()
	stop := context.AfterFunc(ctx, s.shutdown)
	defer func() { stop(); s.shutdown(); s.workers.Wait(); close(s.done) }()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return dial.Wrap("SOCKS 接受连接", err)
		}
		s.mu.Lock()
		if s.closed || len(s.connections) >= s.opts.MaxConnections {
			s.mu.Unlock()
			s.rejected.Add(1)
			_ = conn.Close()
			continue
		}
		s.connections[conn] = struct{}{}
		s.workers.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.workers.Done()
			defer conn.Close()
			defer func() { s.mu.Lock(); delete(s.connections, conn); s.mu.Unlock() }()
			if err := s.handle(ctx, conn, connect); err != nil {
				s.failed.Add(1)
			}
		}()
	}
}

func (s *Server) shutdown() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	cancel := s.cancel
	connections := make([]net.Conn, 0, len(s.connections))
	for c := range s.connections {
		connections = append(connections, c)
	}
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	_ = s.listener.Close()
	for _, c := range connections {
		_ = c.Close()
	}
}

func (s *Server) Close() {
	s.shutdown()
	s.mu.Lock()
	started := s.started
	s.mu.Unlock()
	if started {
		<-s.done
	}
}

func (s *Server) authenticate(username, password []byte) bool {
	u, p := sha256.Sum256(username), sha256.Sum256(password)
	return subtle.ConstantTimeCompare(u[:], s.username[:])&subtle.ConstantTimeCompare(p[:], s.password[:]) == 1
}

// Started 在 Run 已接管接入任务后关闭。
func (s *Server) Started() <-chan struct{} { return s.ready }
