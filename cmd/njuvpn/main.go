// Command njuvpn 是 NJU VPN 的服务端与命令行客户端。
//
// 同一个二进制承担两种角色：
//
//	njuvpn run                                    服务进程（一般由 start 自动拉起）
//	njuvpn start|stop|status|auth|restart         命令行客户端，通过本地 IPC 与服务进程通信
//	njuvpn probe                                  直接连服务端做协议探测，不经过服务进程
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
  %s run                          以服务进程身份运行（一般由 start 自动拉起）
  %s start                        建立隧道（必要时自动拉起服务进程，可能要 %s auth <code>）
  %s stop                         断开隧道，服务进程继续运行
  %s status                       查看服务与隧道状态
  %s auth <code>                  提交短信或 TOTP 验证码
  %s restart                      重启服务进程（改完配置后用它，不必手工杀进程）
  %s probe                        探测协议可用性（直接连服务端，不经过服务进程）
  %s wg-peer <公钥>                更新 WireGuard 接入公钥（不重建隧道）
  %s wg-stats                      查看 WireGuard 收发统计

全局参数:
  -config <path>                  配置文件路径（默认见下）
  -proxy <url>                    覆盖配置文件里的出站代理（run / probe 可用）

默认配置路径:
  Linux    $XDG_CONFIG_HOME/njuvpn/config.yaml（未设置时 ~/.config/njuvpn/config.yaml）
  Windows  %%LOCALAPPDATA%%\njuvpn\config.yaml
`, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog)
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
	case "restart":
		err = cmdRestart(args)
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

	return service.RunServer(svc, cfg.IPC.Endpoint)
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
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	configPath := fs.String("config", "", "配置文件路径")
	if err := fs.Parse(splitFlags(args)); err != nil {
		return err
	}
	// 服务进程没在跑就先拉起来：这是"按需拉起"的入口。
	if err := ensureService(*configPath); err != nil {
		return err
	}
	return runCommand("start", args, ipc.Request{Command: ipc.CmdStart}, 5*time.Minute)
}

func cmdStop(args []string) error {
	return runCommand("stop", args, ipc.Request{Command: ipc.CmdStop}, time.Minute)
}

// cmdRestart 重启服务进程：先请它自己退出（会登出），再拉起一个新的。
//
// 改完配置用它，不必手工杀进程——手工杀会跳过登出，服务端那条名额
// 要等它自己超时才释放，期间同一个账号建不上隧道。
func cmdRestart(args []string) error {
	fs := flag.NewFlagSet("restart", flag.ContinueOnError)
	configPath := fs.String("config", "", "配置文件路径")
	if err := fs.Parse(splitFlags(args)); err != nil {
		return err
	}

	endpoint := serviceEndpoint(*configPath)
	if err := shutdownService(endpoint); err != nil {
		log.Printf("服务进程未在运行（%v），直接拉起", err)
	} else if err := waitServiceGone(endpoint, serviceStopTimeout); err != nil {
		return err
	}
	if err := ensureService(*configPath); err != nil {
		return err
	}
	fmt.Println("服务进程已重启")
	return nil
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
	// -config 仍要能解析（值由下面的 runCommand 自己再解析一遍用来定位端点），
	// 这里只注册、不读。
	_ = fs.String("config", "", "配置文件路径")
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

	// 超时给足：服务端最坏路径是 submitCode + portalToken + acquireIP
	//（3 次尝试 × 30 秒退避），加起来可能超过 3 分钟。
	return runCommand("auth", args, ipc.Request{Command: ipc.CmdAuth, Args: []string{code}}, 5*time.Minute)
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

	// 会话从这一刻起归本函数所有：后面任何一条返回路径都要登出，
	// 否则服务端那条"同一账号只允许一个客户端"的名额会被一直占着
	//（以前就是在提示输入验证码那一步失败时直接 return，漏掉了登出）。
	defer func() {
		if sess == nil {
			return
		}
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

	// 服务端要求二次验证时，向终端索取验证码后在同一个会话里继续。
	if authErr, ok := vpn.AsAuthRequired(err); ok && code == "" {
		prompted, promptErr := askCode(authErr.Kind)
		if promptErr != nil {
			return promptErr
		}
		opt.TwfID = authErr.TwfID
		opt.Code = prompted
		opt.AuthKind = authErr.Kind
		prev := sess
		sess, err = client.Connect(ctx, opt)
		// 续用同一个 TwfID 时只能释放本地资源：对旧对象登出会把正在
		// 续用的服务端会话一起杀掉。
		if prev != nil && prev != sess {
			if sess != nil && prev.TwfID() == sess.TwfID() {
				prev.CloseLocal()
			} else {
				_ = prev.Close(context.Background())
			}
		}
	}

	printTrace(trace)

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
