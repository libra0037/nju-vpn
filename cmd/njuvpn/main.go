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
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/libra0037/nju-vpn/internal/config"
	"github.com/libra0037/nju-vpn/internal/dial"
	"github.com/libra0037/nju-vpn/internal/ipc"
	"github.com/libra0037/nju-vpn/internal/service"
	"github.com/libra0037/nju-vpn/internal/vpn"
	"github.com/libra0037/nju-vpn/internal/wireguard"
)

const prog = "njuvpn"

// startTimeout 是 start 与 auth 两次请求的超时。
//
// 给足：服务端最坏路径是 submitCode + portalToken + acquireIP（3 次尝试 ×
// 30 秒退避），加起来可能超过 3 分钟。
const startTimeout = 5 * time.Minute

// version 是发行版本号，由构建脚本用 -ldflags 注入；
// 源码直接构建时是 dev，便于区分「自己编的」与「下载的」。
var version = "dev"

func usage() {
	fmt.Fprintf(os.Stderr, `%s - NJU VPN 服务端与命令行客户端

用法:
  %s run                          以服务进程身份运行（一般由 start 自动拉起）
  %s start                        建立隧道（必要时自动拉起服务进程，需要时提示输入口令与验证码）
  %s stop                         断开隧道，服务进程继续运行
  %s status                       查看服务与隧道状态
  %s restart                      重启服务进程（改完配置后用它，不必手工杀进程）
  %s probe                        探测协议可用性（直接连服务端，不经过服务进程）
  %s wg-peer <公钥>                更新 WireGuard 接入公钥（不重建隧道）
  %s wg-stats                      查看 WireGuard 收发统计
  %s version                      查看版本号

全局参数:
  -config <path>                  配置文件路径（默认见下）
  -proxy <url>                    覆盖配置文件里的出站代理（run / probe 可用）

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
	case "restart":
		err = cmdRestart(args)
	case "status":
		err = cmdStatus(args)
	case "wg-peer":
		err = cmdSetPeer(args)
	case "wg-stats":
		err = runCommand("wg-stats", args, ipc.Request{Command: ipc.CmdWGStats}, time.Minute)
	case "probe":
		err = cmdProbe(args)
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
		fmt.Fprintf(os.Stderr, "%s: %v\n", prog, err)
		os.Exit(1)
	}
}

// cmdRun 是服务进程入口，由 systemd / SCM 拉起。
func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	configPath := fs.String("config", "", "配置文件路径")
	proxy := fs.String("proxy", "", "覆盖配置文件里的出站代理")
	if _, err := parseInterleaved(fs, args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	// 端口冲突要在登录之前发现：等到承载层启动时才失败，已经白烧了一条
	// 短信与一次建隧道配额。
	if err := precheckListenPort(cfg); err != nil {
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
		log.Printf("出站路径: %s", config.RedactProxy(cfg.Proxy))
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

	return service.RunServer(svc, endpointOf(cfg))
}

// generateWireGuardKey 生成私钥并写回配置文件。
// precheckListenPort 试绑一次承载层的 UDP 端口。
//
// 绑上就立刻关掉，只为尽早给出"端口被占"这个结论，并点名是哪个配置项。
// 同一台机器上跑多个实例时，这是最常见的启动失败原因。
func precheckListenPort(cfg *config.Config) error {
	port := cfg.WireGuard.ListenPort
	if port == 0 {
		return nil // 交给系统分配，不会冲突
	}
	host, err := wireguard.ParseListenHost(cfg.WireGuard.ListenHost)
	if err != nil {
		return err
	}
	addr := "127.0.0.1"
	if host == wireguard.ListenAll {
		addr = "0.0.0.0"
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(addr), Port: port})
	if err != nil {
		return fmt.Errorf("承载层端口 %s:%d 不可用（同一台机器上跑了另一个实例？"+
			"改 wireguard.listen_port 后重启）: %w", addr, port, err)
	}
	conn.Close()
	return nil
}

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

// cmdStart 用一条命令走完整个建立流程。
//
// 配置里没写口令时先问口令（不回显），服务端要求二次验证时再问验证码：
// 用户不再需要先 start 再 auth。口令只经本地套接字传给服务进程，留在
// 它的内存里；验证码是一次性的，也随之用完即弃。
func cmdStart(args []string) error {
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	configPath := fs.String("config", "", "配置文件路径")
	if _, err := parseInterleaved(fs, args); err != nil {
		return err
	}

	cfg, err := clientConfig(*configPath)
	if err != nil {
		return err
	}
	endpoint := endpointOf(cfg)
	password, err := passwordFor(cfg)
	if err != nil {
		return err
	}

	// 服务进程没在跑就先拉起来：这是"按需拉起"的入口。
	if err := ensureService(*configPath); err != nil {
		return err
	}

	req := ipc.Request{Command: ipc.CmdStart}
	if password != "" {
		req.Args = []string{ipc.EncodeSecret(password)}
	}
	resp, err := call(endpoint, req, startTimeout)
	if err != nil {
		return err
	}
	fmt.Println(resp.Message)
	switch resp.Code {
	case ipc.CodeOK:
		return nil
	case ipc.CodeAuthRequired:
		// 需要二次验证：提示输入验证码，然后接着把隧道建起来。
	default:
		return fmt.Errorf("服务进程返回 %d", resp.Code)
	}

	code, err := promptCode()
	if err != nil {
		return err
	}
	if code == "" {
		return errors.New("验证码为空")
	}
	resp, err = call(endpoint, ipc.Request{Command: ipc.CmdAuth, Args: []string{code}}, startTimeout)
	if err != nil {
		return err
	}
	fmt.Println(resp.Message)
	if resp.Code == ipc.CodeOK {
		return nil
	}
	return fmt.Errorf("服务进程返回 %d", resp.Code)
}

// passwordFor 决定本次 start 要不要现问口令。
//
// 配置里写了口令就用配置里的（服务进程自己会读）；没写就现问一遍，只经
// 本地套接字传过去。stdin 是管道时也照读，便于脚本一次喂口令和验证码。
func passwordFor(cfg *config.Config) (string, error) {
	if cfg == nil || cfg.Password != "" {
		return "", nil
	}
	password, err := promptSecret("请输入校园网口令: ")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(password), nil
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
	if _, err := parseInterleaved(fs, args); err != nil {
		return err
	}

	endpoint, err := serviceEndpoint(*configPath)
	if err != nil {
		return err
	}
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
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	configPath := fs.String("config", "", "配置文件路径")
	check := fs.Bool("check", false, "隧道不在 up 状态时以非 0 退出（给巡检脚本用）")
	if _, err := parseInterleaved(fs, args); err != nil {
		return err
	}
	endpoint, err := endpointFor(*configPath)
	if err != nil {
		return err
	}
	req := ipc.Request{Command: ipc.CmdStatus}
	if *check {
		req.Args = []string{"check"}
	}
	return runAt(endpoint, req, 30*time.Second)
}

// cmdSetPeer 更新 WireGuard 接入方的公钥，不重建隧道。
//
//	njuvpn wg-peer <客户端公钥>
func cmdSetPeer(args []string) error {
	fs := flag.NewFlagSet("wg-peer", flag.ContinueOnError)
	configPath := fs.String("config", "", "配置文件路径")
	positional, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	key := strings.TrimSpace(strings.Join(positional, ""))
	if key == "" {
		return errors.New("用法: njuvpn wg-peer <客户端公钥>")
	}
	endpoint, err := endpointFor(*configPath)
	if err != nil {
		return err
	}
	return runAt(endpoint, ipc.Request{Command: ipc.CmdSetPeer, Args: []string{key}}, time.Minute)
}

// parseInterleaved 解析出全部 flag 与位置参数，允许两者交错出现。
//
// Go 的 flag 包遇到第一个位置参数就停止解析，而命令行里这两者经常混着写
// （njuvpn auth 123456 -config x.yaml）。这里循环调用 Parse：每轮吃掉一个
// 位置参数，再从剩下的继续解析。解析语义完全由标准库决定（-flag=value、
// 布尔 flag、-- 终止符都正确），不再自己维护一份 flag 语法。
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return positional, nil
		}
		positional = append(positional, args[0])
		args = args[1:]
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
	force := fs.Bool("force", false, "本机隧道正在运行时也强行探测（会把当前隧道踢下线）")
	debug := fs.Bool("debug", false, "打印每一步的报文")
	if _, err := parseInterleaved(fs, args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *proxy != "" {
		cfg.Proxy = *proxy
	}

	if !*force {
		if err := ensureProbeIsSafe(cfg); err != nil {
			return err
		}
	}

	dialFn, err := dial.New(cfg.Proxy)
	if err != nil {
		return err
	}
	if cfg.Proxy == "" {
		log.Printf("出站路径: 直连")
	} else {
		log.Printf("出站路径: %s", config.RedactProxy(cfg.Proxy))
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
	// 复用已有会话时不需要口令；否则配置里没写就现问一遍（不回显）。
	password := cfg.Password
	if password == "" && *twfID == "" {
		if password, err = promptSecret("请输入校园网口令: "); err != nil {
			return err
		}
		password = strings.TrimSpace(password)
	}
	opt := vpn.ConnectOptions{
		Username: cfg.Username,
		Password: password,
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
