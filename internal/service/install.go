package service

import (
	"fmt"
	"os"

	"github.com/kardianos/service"
)

// 服务名与显示名。
const (
	ServiceName        = "njuvpn"
	ServiceDisplayName = "njuvpn"
	ServiceDescription = "NJU VPN 隧道服务"
)

// serviceConfig 构造操作系统服务的定义。
//
// 关键点是 Restart 策略：短信验证模式下，隧道建立会停在等验证码的状态，
// 进程本身是健康的，不能让 systemd 无限重启它。
func serviceConfig(configPath string) *service.Config {
	args := []string{"run"}
	if configPath != "" {
		args = append(args, "-config", configPath)
	}

	return &service.Config{
		Name:        ServiceName,
		DisplayName: ServiceDisplayName,
		Description: ServiceDescription,
		Arguments:   args,
		Option: service.KeyValue{
			"Restart":           "on-failure",
			"RestartSec":        "5",
			"SuccessExitStatus": "0 2",
		},
	}
}

// InstallService 安装操作系统服务。
func InstallService(configPath string) error {
	s, err := newSystemService(configPath)
	if err != nil {
		return err
	}
	if err := s.Install(); err != nil {
		return fmt.Errorf("安装服务: %w", err)
	}
	return nil
}

// UninstallService 卸载操作系统服务。
func UninstallService(configPath string) error {
	s, err := newSystemService(configPath)
	if err != nil {
		return err
	}
	// 卸载前先停掉，否则有些平台会留下正在运行的进程。
	_ = s.Stop()
	if err := s.Uninstall(); err != nil {
		return fmt.Errorf("卸载服务: %w", err)
	}
	return nil
}

// ControlService 对操作系统服务执行 start / stop / restart。
func ControlService(configPath, action string) error {
	s, err := newSystemService(configPath)
	if err != nil {
		return err
	}

	switch action {
	case "start":
		return s.Start()
	case "stop":
		return s.Stop()
	case "restart":
		return s.Restart()
	default:
		return fmt.Errorf("未知操作 %q", action)
	}
}

// ServiceStatus 查询操作系统服务的状态。
func ServiceStatus(configPath string) (string, error) {
	s, err := newSystemService(configPath)
	if err != nil {
		return "", err
	}
	st, err := s.Status()
	if err != nil {
		return "", err
	}
	switch st {
	case service.StatusRunning:
		return "running", nil
	case service.StatusStopped:
		return "stopped", nil
	default:
		return "unknown", nil
	}
}

func newSystemService(configPath string) (service.Service, error) {
	if configPath == "" {
		configPath = defaultConfigPath()
	}
	return service.New(&program{}, serviceConfig(configPath))
}

// program 只用于让 kardianos/service 探测平台；
// 真正的服务逻辑在 cmdRun 里，不走这里的 Run。
type program struct{}

func (p *program) Start(service.Service) error { return nil }
func (p *program) Stop(service.Service) error  { return nil }

func defaultConfigPath() string {
	if p := os.Getenv("NJUVPON_CONFIG"); p != "" {
		return p
	}
	return ""
}
