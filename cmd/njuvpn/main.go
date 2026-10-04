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

// startTimeout 是需要登录的那些请求的超时。
//
// 给足：最坏路径是登录、发短信、拉资源表、逐个探测隧道节点、建隧道，
// 中间还可能有退避。
const startTimeout = 5 * time.Minute

// version 是发行版本号，由构建脚本用 -ldflags 注入；源码直接构建时是 dev，
// 便于区分"自己编的"与"下载的"。
var version = "dev"

func usage() {
	fmt.Fprintf(os.Stderr, `%s - 把校园网隧道接出成本地 WireGuard 承载

用法:
  %s run                       以服务进程身份运行（一般由 start 自动拉起）
  %s start [--trust]           建立隧道（必要时自动拉起服务进程）
  %s stop                      断开隧道，服务进程继续运行
  %s status [--check] [--json]  查看服务进程、隧道及分类诊断
  %s resources                只打印当前会话的 IPv4 L3 资源及校园 DNS
  %s trust                     把本机绑成授信终端（之后登录免二次验证）
  %s untrust [--all]           解除本机授信；--all 解除该账号下全部授信终端
  %s restart                   重启服务进程（改完配置后用它，不必手工杀进程）
  %s version                   查看版本号

全局参数:
  -config <path>                   配置文件路径（默认见下）

默认配置路径:
  Linux    $XDG_CONFIG_HOME/njuvpn/config.yaml（未设置时 ~/.config/njuvpn/config.yaml）
  Windows  %%LOCALAPPDATA%%\njuvpn\config.yaml
`, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog)
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
		os.Exit(2)
	}

	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintf(os.Stderr, "%s: %v\n", prog, err)
		var ue *usageError
		if errors.As(err, &ue) {
			usage()
			os.Exit(2)
		}
		os.Exit(1)
	}
}

// usageError 表示命令行写法不对（比如多写了位置参数）。退出码 2 与"未知
// 命令"一致：脚本可以据此区分"这条命令根本没执行"与"执行了但失败"。
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

// parseInterleaved 解析出全部 flag 与位置参数，允许两者交错出现。
//
// Go 的 flag 包遇到第一个位置参数就停止解析，而命令行里这两者经常混着写。
// 这里循环调用 Parse：每轮吃掉一个位置参数，再从剩下的继续解析。解析语义
// 完全由标准库决定（-flag=value、布尔 flag、-- 终止符都正确）。
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, err
			}
			return nil, &usageError{err.Error()}
		}
		args = fs.Args()
		if len(args) == 0 {
			return positional, nil
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
}

// parseNoPositional 是各命令的入口：解析出 flag，并拒绝多余的位置参数。
//
// 这些命令都不接受位置参数，而"解析出位置参数再丢掉"会把 `untrust all` 降级
// 成"只解绑本机"——提示语还跟真做了全量一样，一个安全操作被悄悄降级；
// `status extra`、`stop foo` 同理。宁可报用法错误并打印用法。
func parseNoPositional(fs *flag.FlagSet, args []string) error {
	rest, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if len(rest) > 0 {
		return &usageError{fmt.Sprintf("%s: 不接受位置参数，多写了 %q", fs.Name(), rest[0])}
	}
	return nil
}
