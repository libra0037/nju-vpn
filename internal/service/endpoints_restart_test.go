package service

import (
	"context"
	"testing"

	"github.com/libra0037/nju-vpn/internal/ztna"
	"github.com/libra0037/nju-vpn/internal/ztnatest"
)

func TestEndpointRestartBeforeQueuedExitIsHandled(t *testing.T) {
	for _, endpoint := range []string{"wireguard", "socks5"} {
		t.Run(endpoint, func(t *testing.T) {
			srv := newFakeServer(t, ztnatest.Options{})
			cfg := newTestConfig(t, srv)
			cfg.SOCKS5 = socksConfig()
			// 测试协程承担 actor 职责，使退出报告暂留队列；会话和数据任务都真实运行。
			s := &Service{
				cfg:            cfg,
				cred:           credentials{username: cfg.Username, password: cfg.Password},
				status:         newStatusStore(identityOf(cfg)),
				closed:         make(chan struct{}),
				events:         make(chan *command, 16),
				dialer:         srv.Dial,
				controlRootCAs: srv.RootCAs(),
			}
			client, err := s.clientFor()
			if err != nil {
				t.Fatal(err)
			}
			s.session, err = client.Connect(t.Context(), ztna.ConnectOptions{})
			if err != nil {
				t.Fatal(err)
			}
			s.sessionSnapshot.Store(s.session)
			s.status.set(StateLoggingIn, "")
			s.status.set(StateUp, "")
			t.Cleanup(func() {
				s.stopSOCKS()
				s.stopL3()
				if s.br != nil {
					s.br.close()
				}
				if err := s.session.Close(context.Background()); err != nil {
					t.Error(err)
				}
			})
			if err := s.startEndpoint(t.Context(), endpoint); err != nil {
				t.Fatal(err)
			}
			oldGeneration := s.gen
			oldProxy := s.socks
			if endpoint == "wireguard" {
				s.runCancel()
				<-s.runDone
			} else {
				s.socks.Close()
				<-s.socksDone
			}
			if err := s.startEndpoint(t.Context(), endpoint); err != nil {
				t.Fatal(err)
			}
			if !s.Status().Ready || srv.ResourceCalls() != 1 || srv.LogoutCount() != 0 {
				t.Fatal("把已结束任务当成运行中，或重新登录", s.Status())
			}
			if endpoint == "wireguard" {
				if s.gen == oldGeneration || srv.Tunnels() != 2 {
					t.Fatal("没有创建新 L3 任务")
				}
			} else if s.socks == oldProxy {
				t.Fatal("没有创建新 SOCKS 任务")
			}
			kind := cmdTunnelDown
			if endpoint == "socks5" {
				kind = cmdSOCKSDown
			}
			late := &command{kind: kind, gen: oldGeneration, sess: s.session, socks: oldProxy, err: context.Canceled, reply: make(chan error, 1)}
			s.dispatch(late)
			if err := <-late.reply; err != nil || !s.Status().Ready {
				t.Fatal("迟到退出报告终止了新任务", err, s.Status())
			}
		})
	}
}
