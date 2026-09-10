//go:build windows

package service

import (
	"log"

	"github.com/kardianos/service"
)

// windowsProgram 把 IPC 服务端接到 Windows 服务控制管理器上。
//
// 不注册 SCM 的进程会被 SCM 判为启动失败（错误 1053）；而且 SCM 停止服务
// 走的是 TerminateProcess，不接管 Stop 就完全没机会执行登出，
// 服务端会一直挂着一个占名额的会话。
type windowsProgram struct {
	svc      *Service
	endpoint string
	done     chan struct{}
}

func (p *windowsProgram) Start(service.Service) error {
	p.done = make(chan struct{})
	go func() {
		defer close(p.done)
		if err := RunServer(p.svc, p.endpoint); err != nil {
			log.Printf("IPC 服务端退出: %v", err)
		}
	}()
	return nil
}

func (p *windowsProgram) Stop(service.Service) error {
	// Close 内部会等 actor 收尾，其中包含登出。
	p.svc.Close()
	if p.done != nil {
		<-p.done
	}
	return nil
}

// RunPlatform 以当前平台合适的方式运行服务进程。
func RunPlatform(svc *Service, endpoint string) error {
	// 在控制台里手工运行时不需要和 SCM 打交道。
	if service.Interactive() {
		return RunServer(svc, endpoint)
	}

	prog := &windowsProgram{svc: svc, endpoint: endpoint}
	s, err := service.New(prog, &service.Config{Name: ServiceName})
	if err != nil {
		return err
	}
	return s.Run()
}
