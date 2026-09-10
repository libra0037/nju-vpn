package service

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"njuvpn/internal/ipc"
)

const (
	// idleTimeout 是客户端连接的空闲上限。超过它没有任何请求就断开，
	// 免得一个挂死的客户端长期占着文件描述符。
	idleTimeout = 60 * time.Second
	// writeTimeout 限制一次写响应的时间。
	writeTimeout = 15 * time.Second
	// maxConns 限制并发连接数。
	maxConns = 32
)

// Server 在本地端点上提供服务，把 IPC 请求转成对 Service 的调用。
type Server struct {
	svc      *Service
	listener net.Listener

	closing chan struct{}
	once    sync.Once
	sem     chan struct{}
	wg      sync.WaitGroup
}

// NewServer 构造服务端。
func NewServer(svc *Service, listener net.Listener) *Server {
	return &Server{
		svc:      svc,
		listener: listener,
		closing:  make(chan struct{}),
		sem:      make(chan struct{}, maxConns),
	}
}

// Shutdown 停止接受新连接。处理中的连接会自然结束，不在退出路径上等待。
func (s *Server) Shutdown() {
	s.once.Do(func() {
		close(s.closing)
		s.listener.Close()
	})
}

// isClosing 报告服务是否正在关闭。
func (s *Server) isClosing() bool {
	select {
	case <-s.closing:
		return true
	default:
		return false
	}
}

// Serve 开始接受连接，直到 listener 被关闭。
func (s *Server) Serve() error {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		select {
		case s.sem <- struct{}{}:
		default:
			log.Printf("IPC 连接数已达上限 %d，拒绝新连接", maxConns)
			conn.Close()
			continue
		}

		s.wg.Add(1)
		go func() {
			defer func() {
				<-s.sem
				s.wg.Done()
			}()
			s.handle(conn)
		}()
	}
}

// Wait 等待所有在处理的连接结束，仅用于测试与优雅退出。
func (s *Server) Wait() { s.wg.Wait() }

// handle 处理一条客户端连接。
func (s *Server) handle(conn net.Conn) {
	defer conn.Close()

	// panic 边界：一个畸形请求不该带走整个服务进程——服务端的会话
	// 还开着，进程直接死掉就没人登出了。
	defer func() {
		if r := recover(); r != nil {
			log.Printf("处理 IPC 请求时发生内部错误: %v\n%s", r, debug.Stack())
		}
	}()

	reader := bufio.NewReader(conn)
	for {
		// 退出过程中不再接受新请求，避免刚登出又被叫起来建隧道。
		if s.isClosing() {
			return
		}
		if err := conn.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
			return
		}
		req, err := ipc.ReadRequest(reader)
		if err != nil {
			return
		}

		resp := s.dispatch(req)
		if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
			return
		}
		if err := ipc.WriteResponse(conn, resp); err != nil {
			return
		}
	}
}

// dispatch 把一条请求映射成一个响应。
func (s *Server) dispatch(req ipc.Request) ipc.Response {
	switch req.Command {
	case ipc.CmdPing:
		return ipc.Response{Code: ipc.CodeOK, Message: "pong"}

	case ipc.CmdStatus:
		return ipc.Response{Code: ipc.CodeOK, Message: statusLine(s.svc.Status())}

	case ipc.CmdStart:
		err := s.svc.Start()
		switch {
		case err == nil:
			return ipc.Response{Code: ipc.CodeOK, Message: "隧道已建立"}
		case errors.Is(err, ErrAuthRequired):
			return ipc.Response{Code: ipc.CodeAuthRequired, Message: s.svc.Status().Detail}
		case errors.Is(err, ErrShuttingDown):
			return ipc.Response{Code: ipc.CodeRejected, Message: err.Error()}
		default:
			return ipc.Response{Code: ipc.CodeServerError, Message: err.Error()}
		}

	case ipc.CmdAuth:
		if len(req.Args) == 0 {
			return ipc.Response{Code: ipc.CodeBadRequest, Message: "用法: auth <验证码>"}
		}
		// 验证码可能被拆成多个参数（用户敲了空格），拼回去再用。
		code := strings.TrimSpace(strings.Join(req.Args, ""))
		err := s.svc.Auth(code)
		switch {
		case err == nil:
			return ipc.Response{Code: ipc.CodeOK, Message: "验证成功，隧道已建立"}
		case errors.Is(err, ErrAuthRequired):
			return ipc.Response{Code: ipc.CodeAuthRequired, Message: s.svc.Status().Detail}
		case errors.Is(err, ErrShuttingDown):
			return ipc.Response{Code: ipc.CodeRejected, Message: err.Error()}
		default:
			// 验证码错误属于客户端输入问题，不该报成服务端故障。
			return ipc.Response{Code: ipc.CodeBadRequest, Message: err.Error()}
		}

	case ipc.CmdSetPeer:
		if len(req.Args) == 0 {
			return ipc.Response{Code: ipc.CodeBadRequest, Message: "用法: wg-peer <客户端公钥>"}
		}
		key := strings.TrimSpace(strings.Join(req.Args, ""))
		if err := s.svc.SetPeer(key); err != nil {
			return ipc.Response{Code: ipc.CodeBadRequest, Message: err.Error()}
		}
		return ipc.Response{Code: ipc.CodeOK, Message: "已更新 WireGuard 接入公钥"}

	case ipc.CmdWGStats:
		stats, err := s.svc.WireGuardStats()
		if err != nil {
			return ipc.Response{Code: ipc.CodeRejected, Message: err.Error()}
		}
		if len(stats) == 0 {
			return ipc.Response{Code: ipc.CodeOK, Message: "承载层没有接入的 peer"}
		}
		parts := make([]string, 0, len(stats))
		for _, st := range stats {
			line := fmt.Sprintf("peer %s: 收 %d 字节 / 发 %d 字节", st.PublicKey, st.RxBytes, st.TxBytes)
			if st.LastHandshake.IsZero() {
				line += "，尚未握手"
			} else {
				line += fmt.Sprintf("，最近握手 %s", st.LastHandshake.Format("15:04:05"))
			}
			parts = append(parts, line)
		}
		return ipc.Response{Code: ipc.CodeOK, Message: strings.Join(parts, " | ")}

	case ipc.CmdStop:
		err := s.svc.Stop()
		switch {
		case err == nil:
			return ipc.Response{Code: ipc.CodeOK, Message: "隧道已断开"}
		case errors.Is(err, ErrNotRunning):
			return ipc.Response{Code: ipc.CodeRejected, Message: "隧道本来就没有运行"}
		default:
			return ipc.Response{Code: ipc.CodeServerError, Message: err.Error()}
		}

	default:
		return ipc.Response{Code: ipc.CodeBadRequest, Message: "未知命令: " + req.Command}
	}
}

// statusLine 把状态拼成一行文本。
func statusLine(st Status) string {
	msg := string(st.State)
	if st.Detail != "" {
		msg += " | " + st.Detail
	}
	if st.ClientIP != "" {
		msg += " | 校园网地址 " + st.ClientIP
	}
	if st.PeerIP != "" {
		msg += " | peer " + st.PeerIP
	}
	if !st.Since.IsZero() {
		msg += fmt.Sprintf(" | %s 起", st.Since.Format("15:04:05"))
	}
	return msg
}

// RunServer 是服务进程的入口：监听本地端点并处理请求。
// 返回时说明服务已经停止。
func RunServer(svc *Service, endpoint string) error {
	ln, err := ipc.Listen(endpoint)
	if err != nil {
		return err
	}
	log.Printf("服务已启动，监听 %s", endpoint)

	srv := NewServer(svc, ln)

	// 收到退出信号时停止接受连接，让 Serve 返回；
	// 调用方随后执行登出，释放服务端会话。
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-signals
		log.Printf("收到信号 %v，准备退出", sig)
		srv.Shutdown()
	}()
	defer signal.Stop(signals)

	err = srv.Serve()
	srv.Shutdown()
	return err
}
