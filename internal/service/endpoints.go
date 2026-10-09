package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/libra0037/nju-vpn/internal/config"
	"github.com/libra0037/nju-vpn/internal/socks5"
	"github.com/libra0037/nju-vpn/internal/ztna"
)

func newSOCKS(cfg *config.Config) (*socks5.Server, error) {
	c := cfg.SOCKS5
	host := "127.0.0.1"
	if c.ListenHost == "all" {
		host = "0.0.0.0"
	}
	return socks5.New(net.JoinHostPort(host, strconv.Itoa(c.ListenPort)), socks5.Options{Username: c.Username, Password: c.Password, MaxConnections: c.MaxConnections, MaxDials: c.MaxDials})
}

func (s *Service) startL3(ctx context.Context) (err error) {
	if s.runDone != nil {
		select {
		case <-s.runDone:
			s.stopL3()
		default:
			return nil
		}
	}
	defer func() { s.status.endpoint(true, true, err) }()
	if s.br == nil {
		s.br, err = newBearer(s.cfg)
		if err != nil {
			return err
		}
		s.brSnapshot.Store(s.br)
	}
	if err = s.session.StartL3(ctx, s.cfg.WireGuard.MTU); err != nil {
		return err
	}
	if err = s.br.attach(s.session); err != nil {
		s.session.StopL3()
		s.br.detach()
		return err
	}
	if err = ctx.Err(); err != nil {
		s.session.StopL3()
		s.br.detach()
		return err
	}
	runCtx, cancel := context.WithCancel(context.Background())
	s.runCancel = cancel
	s.gen++
	gen, sess := s.gen, s.session
	done := make(chan struct{})
	s.runDone = done
	go func() { defer close(done); s.runTunnel(runCtx, sess, gen) }()
	s.status.setRetrying(false)
	return nil
}

func (s *Service) stopL3() {
	s.gen++ // 任何迟到的局部链路报告均失效，不影响共享会话报告。
	if s.runCancel != nil {
		s.runCancel()
		s.runCancel = nil
	}
	if s.runDone != nil {
		<-s.runDone
		s.runDone = nil
	}
	if s.session != nil {
		s.session.StopL3()
	}
	if s.br != nil {
		s.br.detach()
	}
}

func (s *Service) startSOCKS(operationCtx context.Context) (err error) {
	if s.socksDone != nil {
		select {
		case <-s.socksDone:
			s.stopSOCKS()
		default:
			return nil
		}
	}
	defer func() { s.status.endpoint(false, true, err) }()
	if s.socks == nil {
		s.socks, err = newSOCKS(s.cfg)
		if err != nil {
			return err
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.socksCancel = cancel
	s.socksDone = make(chan struct{})
	done, proxy, sess := s.socksDone, s.socks, s.session
	go func() {
		defer close(done)
		err := proxy.Run(ctx, func(ctx context.Context, target ztna.TCPTarget) (socks5.Stream, error) {
			return sess.DialTCP(ctx, target)
		})
		if err == nil {
			err = errors.New("SOCKS 接入任务已停止")
		}
		s.report(ctx, &command{kind: cmdSOCKSDown, sess: sess, socks: proxy, err: err})
	}()
	select {
	case <-proxy.Started():
	case <-done:
		s.stopSOCKS()
		return errors.New("SOCKS 启动失败")
	case <-operationCtx.Done():
		s.stopSOCKS()
		return operationCtx.Err()
	}
	if err = operationCtx.Err(); err != nil {
		s.stopSOCKS()
		return err
	}
	s.socksSnapshot.Store(proxy)
	return nil
}

func (s *Service) stopSOCKS() {
	s.socksSnapshot.Store(nil)
	if s.socksCancel != nil {
		s.socksCancel()
		s.socksCancel = nil
	}
	if s.socks != nil {
		s.socks.Close()
		s.socks = nil
	}
	if s.socksDone != nil {
		<-s.socksDone
		s.socksDone = nil
	}
}

// StartEndpoint/StopEndpoint 只操作当前已登录会话中的一个端点，不登录或登出。
func (s *Service) StartEndpoint(endpoint string) error {
	return s.call(&command{kind: cmdEndpointStart, endpoint: endpoint})
}
func (s *Service) StopEndpoint(endpoint string) error {
	return s.call(&command{kind: cmdEndpointStop, endpoint: endpoint})
}

func (s *Service) startEndpoint(ctx context.Context, endpoint string) error {
	if s.session == nil || s.status.Get().State != StateUp || s.session.Err() != nil {
		return ErrNotRunning
	}
	var err error
	switch endpoint {
	case "wireguard":
		if !s.cfg.WireGuard.Enabled {
			return fmt.Errorf("%w：配置未启用 WireGuard", ErrBadState)
		}
		err = s.startL3(ctx)
	case "socks5":
		if !s.cfg.SOCKS5.Enabled {
			return fmt.Errorf("%w：配置未启用 SOCKS5", ErrBadState)
		}
		err = s.startSOCKS(ctx)
	default:
		return fmt.Errorf("%w：端点只能是 wireguard 或 socks5", ErrBadState)
	}
	if err == nil {
		s.status.setDetail("指定端点已启动")
	}
	return err
}

func (s *Service) stopEndpoint(endpoint string) error {
	switch endpoint {
	case "wireguard":
		s.stopL3()
		s.brSnapshot.Store(nil)
		if s.br != nil {
			s.br.close()
			s.br = nil
		}
		s.status.endpoint(true, false, nil)
		s.status.setRetrying(false)
	case "socks5":
		s.stopSOCKS()
		s.status.endpoint(false, false, nil)
	default:
		return fmt.Errorf("%w：端点只能是 wireguard 或 socks5", ErrBadState)
	}
	s.status.setDetail("指定端点已停止")
	return nil
}
