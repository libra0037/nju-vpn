// Command njuvpn 是 NJU VPN 的服务端与命令行客户端。
//
// 同一个二进制承担三种角色：
//
//	njuvpn run                              以服务进程身份运行（由 systemd / SCM 拉起）
//	njuvpn start|stop|status|auth           命令行客户端，通过 IPC 与服务进程通信
//	njuvpn service install|uninstall|...    安装、卸载、控制操作系统服务
package main

import (
	"errors"
	"fmt"
	"os"
)

const prog = "njuvpn"

var errNotImplemented = errors.New("not implemented yet")

func usage() {
	fmt.Fprintf(os.Stderr, `%s - NJU VPN 服务端与命令行客户端

用法:
  %s run                          以服务进程身份运行
  %s start                        建立隧道（可能需要 %s auth <code>）
  %s stop                         断开隧道，服务进程继续运行
  %s status                       查看服务与隧道状态
  %s auth <code>                  提交短信或 TOTP 验证码
  %s service install|uninstall    安装 / 卸载操作系统服务
  %s service start|stop|status    控制操作系统服务

全局参数:
  -config <path>                  配置文件路径（默认见下）

默认配置路径:
  Linux    /etc/njuvpn/config.yaml
  Windows  C:\ProgramData\njuvpn\config.yaml
`, prog, prog, prog, prog, prog, prog, prog, prog, prog)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	args := os.Args[2:]

	switch os.Args[1] {
	case "run":
		err = cmdRun(args)
	case "start":
		err = cmdStart(args)
	case "stop":
		err = cmdStop(args)
	case "status":
		err = cmdStatus(args)
	case "auth":
		err = cmdAuth(args)
	case "service":
		err = cmdService(args)
	case "help", "-h", "--help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "%s: 未知命令 %q\n", prog, os.Args[1])
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", prog, err)
		os.Exit(1)
	}
}

func cmdRun(args []string) error    { return errNotImplemented }
func cmdStart(args []string) error  { return errNotImplemented }
func cmdStop(args []string) error   { return errNotImplemented }
func cmdStatus(args []string) error { return errNotImplemented }
func cmdAuth(args []string) error   { return errNotImplemented }
func cmdService(args []string) error { return errNotImplemented }
