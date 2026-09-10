//go:build !windows

package service

// RunPlatform 以当前平台合适的方式运行服务进程。
//
// 非 Windows 平台上进程生命周期由外部服务管理器（systemd 等）负责，
// 直接跑 IPC 服务端即可。
func RunPlatform(svc *Service, endpoint string) error {
	return RunServer(svc, endpoint)
}
