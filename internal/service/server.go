package service

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

	"njuvpn/internal/ipc"
)

// Server 在本地端点上提供服务，把 IPC 请求转成对 Service 的调用。
type Server struct {
	svc      *Service
	listener net.Listener

	wg sync.WaitGroup
}

// NewServer 构造服务端。
func NewServer(svc *Service, listener net.Listener) *Server {
	return &Server{svc: svc, listener: listener}
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
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(conn)
		}()
	}
}

// Shutdown 停止接受新连接并等待处理中的连接结束。
func (s *Server) Shutdown() {
	s.listener.Close()
	s.wg.Wait()
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	for {
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
	return NewServer(svc, ln).Serve()
}
