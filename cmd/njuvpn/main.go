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
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"njuvpn/internal/config"
	"njuvpn/internal/dial"
	"njuvpn/internal/ipc"
	"njuvpn/internal/service"
	"njuvpn/internal/vpn"
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
  %s probe                        探测协议可用性
  %s service install|uninstall    安装 / 卸载操作系统服务
  %s service start|stop|status    控制操作系统服务

全局参数:
  -config <path>                  配置文件路径（默认见下）
  -proxy <url>                    覆盖配置文件里的出站代理

默认配置路径:
  Linux    /etc/njuvpn/config.yaml
  Windows  C:\ProgramData\njuvpn\config.yaml
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
	case "auth":
		err = cmdAuth(args)
	case "probe":
		err = cmdProbe(args)
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

// cmdRun 是服务进程入口，由 systemd / SCM 拉起。
func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	configPath := fs.String("config", "", "配置文件路径")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	log.SetFlags(log.LstdFlags)
	log.Printf("njuvpn 服务进程启动，目标 %s", cfg.ServerAddr())
	if cfg.Proxy != "" {
		log.Printf("出站路径: %s", cfg.Proxy)
	}

	return service.RunServer(service.New(cfg), cfg.IPC.Endpoint)
}

func cmdStart(args []string) error {
	return runCommand("start", args, ipc.Request{Command: ipc.CmdStart})
}

func cmdStop(args []string) error {
	return runCommand("stop", args, ipc.Request{Command: ipc.CmdStop})
}

func cmdStatus(args []string) error {
	return runCommand("status", args, ipc.Request{Command: ipc.CmdStatus})
}

// cmdAuth 提交验证码。不带参数时从终端读，方便交互使用。
func cmdAuth(args []string) error {
	fs := flag.NewFlagSet("auth", flag.ContinueOnError)
	configPath := fs.String("config", "", "配置文件路径")
	// 验证码通常写成 `auth 123456`，后面还可能跟 -config，
	// 所以先把 flag 挑出来再解析，避免位置参数截断解析。
	if err := fs.Parse(splitFlags(args)); err != nil {
		return err
	}

	code := strings.TrimSpace(strings.Join(joinPositional(args), " "))
	if code == "" {
		var err error
		if code, err = promptCode(); err != nil {
			return err
		}
	}

	cfg, err := clientConfig(*configPath)
	if err != nil {
		return err
	}
	resp, err := call(endpointOf(cfg), ipc.Request{Command: ipc.CmdAuth, Args: []string{code}})
	if err != nil {
		return err
	}
	fmt.Println(resp.Message)
	if resp.Code != ipc.CodeOK {
		return fmt.Errorf("服务进程返回 %d", resp.Code)
	}
	return nil
}

// splitFlags 把 -flag value / -flag=value 这类参数挑到前面，其余保持原序。
func splitFlags(args []string) []string {
	var flags, rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			rest = append(rest, a)
			continue
		}
		flags = append(flags, a)
		// -flag value 形式：值不带前缀，且不是下一个 flag
		if !strings.Contains(a, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			flags = append(flags, args[i+1])
			i++
		}
	}
	return append(flags, rest...)
}

// joinPositional 取出不含 flag 的参数。
func joinPositional(args []string) []string {
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			rest = append(rest, a)
			continue
		}
		if !strings.Contains(a, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			i++
		}
	}
	return rest
}

// cmdService 管理操作系统服务（systemd / Windows SCM）。
//
//	njuvpn service install|uninstall|start|stop|restart|status
func cmdService(args []string) error {
	fs := flag.NewFlagSet("service", flag.ContinueOnError)
	configPath := fs.String("config", "", "配置文件路径")
	if err := fs.Parse(args); err != nil {
		return err
	}

	action := ""
	if rest := fs.Args(); len(rest) > 0 {
		action = rest[0]
	}
	if action == "" {
		return errors.New("用法: njuvpn service install|uninstall|start|stop|restart|status")
	}

	switch action {
	case "install":
		if err := service.InstallService(*configPath); err != nil {
			return err
		}
		fmt.Println("服务已安装，可用 njuvpn service start 启动")
		return nil
	case "uninstall":
		if err := service.UninstallService(*configPath); err != nil {
			return err
		}
		fmt.Println("服务已卸载")
		return nil
	case "status":
		st, err := service.ServiceStatus(*configPath)
		if err != nil {
			return err
		}
		fmt.Println(st)
		return nil
	case "start", "stop", "restart":
		if err := service.ControlService(*configPath, action); err != nil {
			return err
		}
		fmt.Printf("服务已 %s\n", action)
		return nil
	default:
		return fmt.Errorf("未知操作 %q", action)
	}
}

// cmdProbe 走一遍完整的协议握手，用来验证服务端仍然接受当前的客户端实现。
//
//	njuvpn probe -config config.yaml [-proxy http://127.0.0.1:7897] [-totp <code>] [-debug]
func cmdProbe(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	configPath := fs.String("config", "", "配置文件路径")
	proxy := fs.String("proxy", "", "覆盖配置文件里的出站代理")
	totpCode := fs.String("totp", "", "TOTP 验证码，留空则用配置里的密钥自动生成")
	twfId := fs.String("twf-id", "", "复用已有的 TwfID，跳过 Web 登录（调试用）")
	logout := fs.Bool("logout", false, "只调用服务端登出接口然后退出，不建立隧道")
	debug := fs.Bool("debug", false, "打印每一步的报文")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	proxyURL := cfg.Proxy
	if *proxy != "" {
		proxyURL = *proxy
	}

	dialFn, err := dial.New(proxyURL)
	if err != nil {
		return err
	}
	if proxyURL == "" {
		log.Printf("出站路径: 直连")
	} else {
		log.Printf("出站路径: %s", proxyURL)
	}

	client := vpn.NewClient(cfg.ServerAddr(), dialFn)
	if addr := cfg.DialAddr(); addr != "" {
		client.WithDialAddr(addr)
		log.Printf("连接地址覆盖为 %s", addr)
	}

	if *logout {
		if *twfId == "" {
			return errors.New("-logout 需要配合 -twf-id 指定要登出的会话")
		}
		if err := client.Logout(*twfId); err != nil {
			return err
		}
		fmt.Println("服务端已注销该会话")
		return nil
	}

	code := *totpCode
	if code == "" && cfg.TOTPSecret != "" {
		code, err = vpn.GenerateTOTP(cfg.TOTPSecret)
		if err != nil {
			return err
		}
		log.Printf("已用配置文件里的密钥生成 TOTP 验证码")
	}

	res, probeErr := client.Probe(cfg.Username, cfg.Password, *twfId, code, *debug, askCode)

	fmt.Printf("\n%-20s %-10s %s\n", "阶段", "耗时", "结果")
	for _, s := range res.Stages {
		status := "OK"
		if s.Err != nil {
			status = s.Err.Error()
		}
		fmt.Printf("%-20s %-10s %s\n", s.Name, s.Duration.Round(time.Millisecond), status)
	}
	fmt.Printf("\n%s\n", res.Summary())
	if res.TwfID != "" {
		fmt.Printf("TwfID: %s（可用 -twf-id 复用，跳过再次登录）\n", res.TwfID)
	}

	return probeErr
}

// askCode 在服务端要求二次验证时向终端索取验证码。
// 短信验证码只在当前登录会话内有效，所以必须在同一次 Probe 里提交。
func askCode(kind error) (string, error) {
	if errors.Is(kind, vpn.ERR_NEXT_AUTH_SMS) {
		fmt.Print("服务端已发送短信验证码，请输入: ")
	} else {
		fmt.Print("请输入 TOTP 验证码: ")
	}
	var code string
	if _, err := fmt.Scanln(&code); err != nil {
		return "", err
	}
	return strings.TrimSpace(code), nil
}
