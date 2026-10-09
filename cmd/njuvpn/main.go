// Command njuvpn 把校园网隧道接出成一个本地 WireGuard 承载。
//
// 同一个二进制承担两种角色：
//
//	njuvpn run                       服务进程（一般由 start 自动拉起）
//	njuvpn start|stop|status|...     命令行客户端，通过本地 IPC 与服务进程通信
//
// 命令行是纯客户端：它不做协议交互，也不长期活着。所有需要登录、需要长期
// 保持连接的事情都在服务进程里做，两者之间只有一条本地套接字。
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"
)

const prog = "njuvpn"

// 退出码是命令行契约；3、4 仅用于 status 的正常查询结果。
const (
	exitSuccess           = 0
	exitFailure           = 1
	exitUsage             = 2
	exitServiceNotRunning = 3
	exitTunnelNotReady    = 4
)

// startTimeout 是需要登录的那些请求的超时。
//
// 给足：最坏路径是登录、发短信、拉资源表、逐个探测隧道节点、建隧道，
// 中间还可能有退避。
const startTimeout = 5 * time.Minute

// version 是发行版本号，由构建脚本用 -ldflags 注入；源码直接构建时是 dev，
// 便于区分"自己编的"与"下载的"。
var version = "dev"

func usage() {
	fmt.Fprintf(os.Stderr, `%s - 通过 WireGuard / SOCKS5 访问校园资源

用法:
  %s run                       以服务进程身份运行（一般由 start 自动拉起）
  %s start [--trust] [--endpoint <wireguard|socks5>]  登录并启动配置的端点；单端点操作要求已登录
  %s stop [--endpoint <wireguard|socks5>]  全局断开并登出，或只停止指定端点
  %s status [--json]           查看服务进程、隧道及分类诊断
  %s resources                只打印当前会话的 IP / TCP 域名资源及校园 DNS
  %s trust                     把本机绑成授信终端（之后登录免二次验证）
  %s untrust [--all]           解除本机授信；--all 解除该账号下全部授信终端
  %s restart                   重启服务进程（改完配置后用它，不必手工杀进程）
  %s version                   查看版本号

全局参数:
  -config <path>                   配置文件路径（默认见下）

status 退出码:
  0 共享登录和当前启用端点就绪；1 查询失败；2 用法错误
  3 服务进程未运行；4 数据端点未就绪（未登录、待验证、失败、停止或重连）

默认配置路径:
  Linux    $XDG_CONFIG_HOME/njuvpn/config.yaml（未设置时 ~/.config/njuvpn/config.yaml）
  Windows  %%LOCALAPPDATA%%\njuvpn\config.yaml
`, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(exitUsage)
	}

	var err error
	code := exitSuccess
	args := os.Args[2:]

	switch os.Args[1] {
	case "run":
		err = cmdRun(args)
	case "start":
		err = cmdStart(args)
	case "stop":
		err = cmdStop(args)
	case "status":
		code, err = cmdStatus(args)
	case "resources":
		err = cmdResources(args)
	case "trust":
		err = cmdTrust(args)
	case "untrust":
		err = cmdUntrust(args)
	case "restart":
		err = cmdRestart(args)
	case "version", "-v", "--version":
		fmt.Printf("%s %s\n", prog, version)
		return
	case "help", "-h", "--help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "%s: 未知命令 %q\n", prog, os.Args[1])
		usage()
		os.Exit(exitUsage)
	}

	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintf(os.Stderr, "%s: %v\n", prog, err)
		var ue *usageError
		if errors.As(err, &ue) {
			usage()
			os.Exit(exitUsage)
		}
		if code == exitSuccess {
			code = exitFailure
		}
	}
	if code != exitSuccess {
		os.Exit(code)
	}
}

// usageError 表示命令行写法不对（比如多写了位置参数）。退出码 2 与"未知
// 命令"一致：脚本可以据此区分"这条命令根本没执行"与"执行了但失败"。
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

// parseNoPositional 是各命令的入口：解析出 flag，并拒绝多余的位置参数。
//
// 这些命令都不接受位置参数，而"解析出位置参数再丢掉"会把 `untrust all` 降级
// 成"只解绑本机"——提示语还跟真做了全量一样，一个安全操作被悄悄降级；
// `status extra`、`stop foo` 同理。宁可报用法错误并打印用法。
func parseNoPositional(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return &usageError{err.Error()}
	}
	if fs.NArg() > 0 {
		return &usageError{fmt.Sprintf("%s: 不接受位置参数，多写了 %q", fs.Name(), fs.Arg(0))}
	}

	return nil
}
