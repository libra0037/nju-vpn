// Command njuvpn 是 NJU VPN 的服务端与命令行客户端。
//
// 同一个二进制承担三种角色：
//
//	njuvpn run                              以服务进程身份运行（由 systemd / SCM 拉起）
//	njuvpn start|stop|status|auth           命令行客户端，通过 IPC 与服务进程通信
//	njuvpn service install|uninstall|...    安装、卸载、控制操作系统服务
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"njuvpn/internal/config"
	"njuvpn/internal/dial"
	"njuvpn/internal/ipc"
	"njuvpn/internal/service"
	"njuvpn/internal/vpn"
	"njuvpn/internal/wireguard"
)

const prog = "njuvpn"

func usage() {
	fmt.Fprintf(os.Stderr, `%s - NJU VPN 服务端与命令行客户端

用法:
  %s run                          以服务进程身份运行
  %s start                        建立隧道（可能需要 %s auth <code>）
  %s stop                         断开隧道，服务进程继续运行
  %s status                       查看服务与隧道状态
  %s auth <code>                  提交短信或 TOTP 验证码
  %s probe                        探测协议可用性
  %s wg-peer <公钥>                更新 WireGuard 接入公钥（不重建隧道）
  %s wg-stats                      查看 WireGuard 收发统计
  %s service install|uninstall    安装 / 卸载操作系统服务
  %s service start|stop|status    控制操作系统服务

全局参数:
  -config <path>                  配置文件路径（默认见下）
  -proxy <url>                    覆盖配置文件里的出站代理（run / probe 可用）

默认配置路径:
  Linux    /etc/njuvpn/config.yaml
  Windows  C:\ProgramData\njuvpn\config.yaml
`, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog)
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
	case "wg-peer":
		err = cmdSetPeer(args)
	case "wg-stats":
		err = runCommand("wg-stats", args, ipc.Request{Command: ipc.CmdWGStats}, time.Minute)
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
	proxy := fs.String("proxy", "", "覆盖配置文件里的出站代理")
	if err := fs.Parse(splitFlags(args)); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *proxy != "" {
		cfg.Proxy = *proxy
	}

	log.SetFlags(log.LstdFlags)
	log.Printf("%s 服务进程启动，目标 %s", prog, cfg.ServerAddr())
	for _, w := range cfg.Warnings() {
		log.Printf("警告: %s", w)
	}
	if cfg.Proxy != "" {
		log.Printf("出站路径: %s", cfg.Proxy)
	}

	// WireGuard 私钥缺失时生成一个并写回配置：服务端公钥要填到客户端配置里，
	// 每次重启换一个会让客户端配置失效。
	if cfg.WireGuard.PrivateKey == "" {
		if err := generateWireGuardKey(cfg); err != nil {
			log.Printf("警告: %v", err)
		}
	}
	logWireGuardPublicKey(cfg)

	svc := service.New(cfg)
	// 退出路径上无条件登出：服务端同一账号只允许一个客户端，
	// 残留会话会让后续建隧道被拒。这里相当于 atexit。
	defer svc.Close()

	return service.RunPlatform(svc, cfg.IPC.Endpoint)
}

// generateWireGuardKey 生成私钥并写回配置文件。
func generateWireGuardKey(cfg *config.Config) error {
	key, err := wireguard.GenerateKey()
	if err != nil {
		return fmt.Errorf("生成 WireGuard 私钥失败: %w", err)
	}
	cfg.WireGuard.PrivateKey = key.String()
	if err := config.PersistPrivateKey(cfg.SourcePath(), key.String()); err != nil {
		return fmt.Errorf("私钥已生成但无法写回 %s（%v）；重启后公钥会变，客户端需要重新配置",
			cfg.SourcePath(), err)
	}
	log.Printf("已生成 WireGuard 私钥并写回 %s", cfg.SourcePath())
	return nil
}

// logWireGuardPublicKey 打印服务端公钥，用户需要把它填进客户端配置。
func logWireGuardPublicKey(cfg *config.Config) {
	if cfg.WireGuard.PrivateKey == "" {
		return
	}
	key, err := wireguard.ParseKey(cfg.WireGuard.PrivateKey)
	if err != nil {
		log.Printf("警告: wireguard.private_key 无法解析: %v", err)
		return
	}
	pub, err := key.PublicKey()
	if err != nil {
		log.Printf("警告: 推导 WireGuard 公钥失败: %v", err)
		return
	}
	log.Printf("WireGuard 服务端公钥: %s", pub.String())
}

func cmdStart(args []string) error {
	return runCommand("start", args, ipc.Request{Command: ipc.CmdStart}, 5*time.Minute)
}

func cmdStop(args []string) error {
	return runCommand("stop", args, ipc.Request{Command: ipc.CmdStop}, time.Minute)
}

func cmdStatus(args []string) error {
	return runCommand("status", args, ipc.Request{Command: ipc.CmdStatus}, 30*time.Second)
}

// cmdSetPeer 更新 WireGuard 接入方的公钥，不重建隧道。
//
//	njuvpn wg-peer <客户端公钥>
func cmdSetPeer(args []string) error {
	key := strings.TrimSpace(strings.Join(joinPositional(args), ""))
	if key == "" {
		return errors.New("用法: njuvpn wg-peer <客户端公钥>")
	}
	return runCommand("wg-peer", args, ipc.Request{Command: ipc.CmdSetPeer, Args: []string{key}}, time.Minute)
}

// cmdAuth 提交验证码。不带参数时从终端读，方便交互使用。
func cmdAuth(args []string) error {
	fs := flag.NewFlagSet("auth", flag.ContinueOnError)
	configPath := fs.String("config", "", "配置文件路径")
	// 验证码通常写成 auth 123456，后面还可能跟 -config，
	// 所以先把 flag 挑出来再解析，避免位置参数截断解析。
	if err := fs.Parse(splitFlags(args)); err != nil {
		return err
	}

	code := strings.TrimSpace(strings.Join(joinPositional(args), ""))
	if code == "" {
		var err error
		if code, err = promptCode(); err != nil {
			return err
		}
	}

	endpoint := endpointOf(clientConfig(*configPath))
	// 提交验证码前确认连的是服务进程自己的套接字。
	if err := ipc.VerifyPeer(endpoint); err != nil {
		return err
	}

	return runCommand("auth", args, ipc.Request{Command: ipc.CmdAuth, Args: []string{code}}, 2*time.Minute)
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
	// flag 解析会在第一个非 flag 参数处停下，service install -config x
	// 里的 -config 会被静默丢掉，所以先重排参数。
	if err := fs.Parse(splitFlags(args)); err != nil {
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
	twfID := fs.String("twf-id", "", "复用已有的 TwfID，跳过 Web 登录（调试用）")
	logout := fs.Bool("logout", false, "只调用服务端登出接口然后退出，不建立隧道")
	keep := fs.Bool("keep", false, "探测结束后不登出，保留服务端会话以便复用")
	debug := fs.Bool("debug", false, "打印每一步的报文")
	if err := fs.Parse(splitFlags(args)); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *proxy != "" {
		cfg.Proxy = *proxy
	}

	dialFn, err := dial.New(cfg.Proxy)
	if err != nil {
		return err
	}
	if cfg.Proxy == "" {
		log.Printf("出站路径: 直连")
	} else {
		log.Printf("出站路径: %s", cfg.Proxy)
	}

	client := vpn.New(vpn.Options{
		Server:   cfg.ServerAddr(),
		DialAddr: cfg.DialAddr(),
		Dial:     dialFn,
	})
	defer client.CloseIdleConnections()

	// Ctrl-C 能立刻中断探测，不再需要等满退避。
	ctx, cancel := signalContext()
	defer cancel()

	if *logout {
		if *twfID == "" {
			return errors.New("-logout 需要配合 -twf-id 指定要登出的会话")
		}
		if err := client.Logout(ctx, *twfID); err != nil {
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

	trace := &vpn.Trace{}
	opt := vpn.ConnectOptions{
		Username: cfg.Username,
		Password: cfg.Password,
		TwfID:    *twfID,
		Code:     code,
		Debug:    *debug,
		Trace:    trace,
	}

	sess, err := client.Connect(ctx, opt)
	// 服务端要求二次验证时，向终端索取验证码后在同一个会话里继续。
	if authErr, ok := vpn.AsAuthRequired(err); ok && code == "" {
		prompted, promptErr := askCode(authErr.Kind)
		if promptErr != nil {
			return promptErr
		}
		opt.TwfID = authErr.TwfID
		opt.Code = prompted
		opt.AuthKind = authErr.Kind
		sess, err = client.Connect(ctx, opt)
	}

	printTrace(trace)

	if sess != nil {
		defer func() {
			if *keep {
				sess.CloseLocal()
				return
			}
			if closeErr := sess.Close(context.Background()); closeErr != nil {
				fmt.Printf("登出未成功: %v\n", closeErr)
			} else {
				fmt.Printf("已登出并释放服务端会话\n")
			}
		}()
	}
	if err != nil {
		return err
	}

	if *keep {
		fmt.Printf("TwfID: %s（可用 -twf-id 复用，跳过再次登录）\n", sess.TwfID())
	}

	if err := trace.Step("tunnel-handshake", func() error { return sess.CheckTunnel(ctx) }); err != nil {
		printTrace(trace)
		return err
	}
	printTrace(trace)
	fmt.Printf("\n%s\n", trace.Summary())
	return nil
}

// printTrace 打印各阶段结果。
func printTrace(t *vpn.Trace) {
	fmt.Printf("\n%-20s %-10s %s\n", "阶段", "耗时", "结果")
	for _, s := range t.Stages() {
		status := "OK"
		if s.Err != nil {
			status = s.Err.Error()
		}
		fmt.Printf("%-20s %-10s %s\n", s.Name, s.Duration.Round(time.Millisecond), status)
	}
}

// askCode 在服务端要求二次验证时向终端索取验证码。
// 短信验证码只在当前登录会话内有效，所以必须在同一次连接里提交。
func askCode(kind error) (string, error) {
	if errors.Is(kind, vpn.ErrAuthSMS) {
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

// signalContext 返回一个在收到中断信号时取消的上下文。
func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-signals:
			fmt.Fprintln(os.Stderr, "已中断")
			cancel()
		case <-ctx.Done():
		}
		signal.Stop(signals)
	}()
	return ctx, cancel
}
