package service

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"njuvpn/internal/ipc"
)

// Server 在本地端点上提供服务，把 IPC 请求转成对 Service 的调用。
type Server struct {
	svc      *Service
	listener net.Listener

	closing chan struct{}
	once    sync.Once
}

// NewServer 构造服务端。
func NewServer(svc *Service, listener net.Listener) *Server {
	return &Server{svc: svc, listener: listener, closing: make(chan struct{})}
}

// Shutdown 停止接受新连接。处理中的连接会自然结束，不在退出路径上等待，
// 以免被 probe 的长时间重试拖住进程退出。
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
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	for {
		// 退出过程中不再接受新请求，避免刚登出又被叫起来建隧道。
		if s.isClosing() {
			return
		}
		req, err := ipc.ReadRequest(reader)
		if err != nil {
			return
		}

		resp := s.dispatch(req)
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
		st := s.svc.Status()
		msg := string(st.State)
		if st.Detail != "" {
			msg += " | " + st.Detail
		}
		if st.ClientIP != "" {
			msg += fmt.Sprintf(" | 校园网地址 %s", st.ClientIP)
		}
		if st.PeerIP != "" {
			msg += fmt.Sprintf(" | peer %s", st.PeerIP)
		}
		return ipc.Response{Code: ipc.CodeOK, Message: msg}

	case ipc.CmdStart:
		err := s.svc.Start()
		switch {
		case err == nil:
			return ipc.Response{Code: ipc.CodeOK, Message: "隧道已建立"}
		case errors.Is(err, ErrAuthRequired):
			// 409 让客户端知道要接着调用 auth，而不是当成失败。
			return ipc.Response{Code: ipc.CodeRejected, Message: s.svc.Status().Detail}
		default:
			return ipc.Response{Code: ipc.CodeServerError, Message: err.Error()}
		}

	case ipc.CmdAuth:
		if len(req.Args) == 0 {
			return ipc.Response{Code: ipc.CodeBadRequest, Message: "用法: auth <验证码>"}
		}
		code := strings.TrimSpace(req.Args[0])
		if err := s.svc.Auth(code); err != nil {
			if errors.Is(err, ErrAuthRequired) {
				return ipc.Response{Code: ipc.CodeRejected, Message: s.svc.Status().Detail}
			}
			return ipc.Response{Code: ipc.CodeServerError, Message: err.Error()}
		}
		return ipc.Response{Code: ipc.CodeOK, Message: "验证成功，隧道已建立"}

	case ipc.CmdStop:
		if err := s.svc.Stop(); err != nil {
			if errors.Is(err, ErrNotRunning) {
				return ipc.Response{Code: ipc.CodeRejected, Message: "隧道本来就没有运行"}
			}
			return ipc.Response{Code: ipc.CodeServerError, Message: err.Error()}
		}
		return ipc.Response{Code: ipc.CodeOK, Message: "隧道已断开"}

	default:
		return ipc.Response{Code: ipc.CodeBadRequest, Message: "未知命令: " + req.Command}
	}
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
	// 调用方随后通过 defer 执行登出，释放服务端会话。
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
