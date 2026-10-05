package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/libra0037/nju-vpn/internal/config"
	"github.com/libra0037/nju-vpn/internal/ipc"
	"github.com/libra0037/nju-vpn/internal/service"
	"github.com/libra0037/nju-vpn/internal/wireguard"
	"github.com/libra0037/nju-vpn/internal/ztna"
)

// cmdRun 是服务进程入口：由命令行按需拉起，也可以直接在终端里跑。
func cmdRun(args []string) (resultErr error) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	configPath := fs.String("config", "", "配置文件路径")
	if err := parseNoPositional(fs, args); err != nil {
		return err
	}
	closeLogger, err := daemonLogger()
	if err != nil {
		return err
	}
	defer closeLogger()
	defer func() {
		if resultErr != nil && os.Getenv(daemonLogEnv) != "" {
			log.Printf("服务进程启动或运行失败: %v", resultErr)
		}
	}()

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	endpoint := endpointOf(cfg)
	ln, err := ipc.Listen(endpoint)
	if err != nil {
		return err
	}
	defer ln.Close()
	log.SetFlags(log.LstdFlags)
	// 第一行就报出身份：同机多实例时日志几乎逐字相同，没有这一行就分不清
	// 眼前这份日志属于哪个实例。
	log.Printf("%s 服务进程启动 pid=%d 账号=%q 配置=%q 端点=%q",
		prog, os.Getpid(), cfg.Username, cfg.SourcePath(), endpoint)
	for _, w := range cfg.Warnings() {
		log.Printf("警告: %s", w)
	}
	if cfg.Proxy != "" {
		log.Printf("已配置出站代理")
	}

	if err := ensureIdentity(cfg); err != nil {
		return err
	}
	logWireGuardPublicKey(cfg)

	// 承载设备在这里就建起来：端口被占、密钥写错这类问题必须在启动时报
	// 出来，而不是等用户输完验证码、白烧一条短信之后。
	svc, err := service.New(cfg)
	if err != nil {
		return err
	}
	log.Printf("WireGuard 承载: %s", svc.BearerSummary())

	// 退出路径上无条件登出：服务端同一账号只允许一条隧道会话，残留会话会让
	// 后续建隧道被拒。这里相当于 atexit。
	defer svc.Close()

	return service.RunServer(svc, ln)
}

// 实例端点已被当前进程独占；身份自举必须持久化成功后才采用。
func ensureIdentity(cfg *config.Config) error {
	saved, err := config.InitializeIdentity(cfg.SourcePath(), func() (string, string, error) {
		id, err := ztna.NewDeviceID()
		if err != nil {
			return "", "", err
		}
		key, err := wireguard.GenerateKey()
		if err != nil {
			return "", "", err
		}
		return id, key.String(), nil
	})
	if err != nil {
		return err
	}
	*cfg = *saved
	return nil
}

// logWireGuardPublicKey 打印承载层公钥，用户需要把它填进对端配置。
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
	log.Printf("WireGuard 承载层公钥: %s", pub.String())
}

// cmdStart 用一条命令走完整个建立流程。
//
// 配置里没写口令时先问口令（不回显），服务端要求二次验证时再问验证码：用户
// 不必先 start 再 auth。口令只经本地套接字传给服务进程，留在它的内存里；
// 验证码是一次性的，随之用完即弃。
func cmdStart(args []string) error {
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	configPath := fs.String("config", "", "配置文件路径")
	trust := fs.Bool("trust", false, "把本机绑成授信终端（之后登录免二次验证）")
	if err := parseNoPositional(fs, args); err != nil {
		return err
	}

	cfg, err := clientConfig(*configPath)
	if err != nil {
		return err
	}
	endpoint := endpointOf(cfg)
	password, err := passwordFor(cfg, endpoint)
	if err != nil {
		return err
	}
	if err := ensureService(*configPath); err != nil {
		return err
	}

	req := ipc.Request{Command: ipc.CmdStart, Args: []string{boolArg("trust", *trust)}}
	if password != "" {
		req.Args = append(req.Args, ipc.EncodeSecret(password))
	}
	resp, err := call(endpoint, req, startTimeout)
	if err != nil {
		return err
	}
	return finish(endpoint, resp)
}

// cmdTrust 把本机绑成授信终端。
//
// 隧道在跑时服务进程会复用当前会话，所以这条命令通常既不需要口令也不需要
// 验证码；隧道没在跑时才需要为这次操作登录一次。
func cmdTrust(args []string) error {
	fs := flag.NewFlagSet("trust", flag.ContinueOnError)
	configPath := fs.String("config", "", "配置文件路径")
	if err := parseNoPositional(fs, args); err != nil {
		return err
	}
	return deviceCommand(*configPath, ipc.CmdTrust, nil)
}

// cmdUntrust 解除授信：默认只解除本机，--all 解除该账号下全部授信终端。
func cmdUntrust(args []string) error {
	fs := flag.NewFlagSet("untrust", flag.ContinueOnError)
	configPath := fs.String("config", "", "配置文件路径")
	all := fs.Bool("all", false, "解除该账号下全部授信终端，不只是本机")
	if err := parseNoPositional(fs, args); err != nil {
		return err
	}
	return deviceCommand(*configPath, ipc.CmdUntrust, []string{boolArg("all", *all)})
}

// deviceCommand 是 trust 与 untrust 的公共流程：必要时拉起服务进程、必要时
// 先问口令，然后发请求并在服务端要求验证码时接着把码送回去。
func deviceCommand(configPath, command string, args []string) error {
	cfg, err := clientConfig(configPath)
	if err != nil {
		return err
	}
	endpoint := endpointOf(cfg)
	password, err := passwordFor(cfg, endpoint)
	if err != nil {
		return err
	}
	if err := ensureService(configPath); err != nil {
		return err
	}
	if password != "" {
		args = append(args, ipc.EncodeSecret(password))
	}

	resp, err := call(endpoint, ipc.Request{Command: command, Args: args}, startTimeout)
	if err != nil {
		return err
	}
	return finish(endpoint, resp)
}

func cmdStop(args []string) error {
	return runCommand("stop", args, ipc.Request{Command: ipc.CmdStop}, time.Minute)
}

// cmdStatus 只读查询；输出格式不改变退出码，未就绪结果不作为查询错误。
func cmdStatus(args []string) (int, error) {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	configPath := fs.String("config", "", "配置文件路径")
	jsonOutput := fs.Bool("json", false, "打印只读状态与分类诊断 JSON")
	if err := parseNoPositional(fs, args); err != nil {
		return exitUsage, err
	}
	endpoint, err := endpointFor(*configPath)
	if err != nil {
		return exitFailure, err
	}
	req := ipc.Request{Command: ipc.CmdStatus}
	if *jsonOutput {
		req.Args = append(req.Args, "json")
	}
	resp, err := call(endpoint, req, 30*time.Second)
	if err != nil {
		if errors.Is(err, ipc.ErrNotRunning) {
			return exitServiceNotRunning, err
		}
		return exitFailure, err
	}
	fmt.Println(resp.Message)
	switch resp.Code {
	case ipc.CodeOK:
		return exitSuccess, nil
	case ipc.CodeRejected:
		return exitTunnelNotReady, nil
	default:
		return exitFailure, fmt.Errorf("状态查询失败，服务进程返回 %d", resp.Code)
	}
}

// cmdRestart 重启服务进程：先请它自己退出（会登出），再拉起一个新的。
//
// 改完配置用它，不必手工杀进程——手工杀会跳过登出，服务端那条名额要等它
// 自己超时才释放，期间同一个账号建不上隧道。
func cmdRestart(args []string) error {
	fs := flag.NewFlagSet("restart", flag.ContinueOnError)
	configPath := fs.String("config", "", "配置文件路径")
	if err := parseNoPositional(fs, args); err != nil {
		return err
	}

	endpoint, err := endpointFor(*configPath)
	if err != nil {
		return err
	}
	if err := shutdownService(endpoint); err != nil {
		if !errors.Is(err, ipc.ErrNotRunning) {
			return err
		}
	} else if err := waitServiceGone(endpoint, serviceStopTimeout, pingService); err != nil {
		return err
	}
	if err := ensureService(*configPath); err != nil {
		return err
	}
	fmt.Println("服务进程已重启")
	return nil
}

// boolArg 把布尔值编成 IPC 的固定位置参数（见 ipc 包的说明）。
func boolArg(name string, v bool) string {
	if v {
		return name + "=1"
	}
	return name + "=0"
}
