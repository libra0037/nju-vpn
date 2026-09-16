package main

import (
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
func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	configPath := fs.String("config", "", "配置文件路径")
	if err := parseNoPositional(fs, args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	endpoint := endpointOf(cfg)
	log.SetFlags(log.LstdFlags)
	// 第一行就报出身份：同机多实例时日志几乎逐字相同，没有这一行就分不清
	// 眼前这份日志属于哪个实例。
	log.Printf("%s 服务进程启动 pid=%d 账号=%s 配置=%s 端点=%s",
		prog, os.Getpid(), cfg.Username, cfg.SourcePath(), endpoint)
	log.Printf("目标 %s", cfg.ConnectAddr())
	for _, w := range cfg.Warnings() {
		log.Printf("警告: %s", w)
	}
	if cfg.Proxy != "" {
		log.Printf("出站路径: %s", config.RedactProxy(cfg.Proxy))
	}

	ensureIdentity(cfg)
	logWireGuardPublicKey(cfg)

	// 承载设备在这里就建起来：端口被占、密钥写错这类问题必须在启动时报
	// 出来，而不是等用户输完验证码、白烧一条短信之后。
	svc, err := service.New(cfg)
	if err != nil {
		return err
	}
	log.Printf("WireGuard 承载: %s", svc.BearerSummary())

	// 退出路径上无条件登出：服务端同一账号只允许一个客户端，残留会话会让
	// 后续建隧道被拒。这里相当于 atexit。
	defer svc.Close()

	return service.RunServer(svc, endpoint)
}

// ensureIdentity 保证设备标识与 WireGuard 私钥存在，并尽量写回配置文件。
//
// 两者都必须在服务进程启动时定下来：设备标识决定授信终端绑的是哪台设备，
// 换一个就得重新做一次二次验证；私钥换一个，所有客户端配置都会失效。
//
// 写回失败只记警告：配置可能是只读的，那种情况下进程仍然能跑，只是下次
// 启动会换一个标识——用户需要知道这一点。
func ensureIdentity(cfg *config.Config) {
	if cfg.DeviceID == "" {
		id := ztna.NewDeviceID()
		cfg.DeviceID = id
		if err := config.PersistDeviceID(cfg.SourcePath(), id); err != nil {
			log.Printf("警告: 设备标识已生成但无法写回配置（%v）；下次启动会换一个，授信终端会跟着失效", err)
		} else {
			log.Printf("已生成设备标识并写回 %s", cfg.SourcePath())
		}
	}
	if cfg.WireGuard.PrivateKey == "" {
		key, err := wireguard.GenerateKey()
		if err != nil {
			log.Printf("警告: 生成 WireGuard 私钥失败: %v", err)
			return
		}
		cfg.WireGuard.PrivateKey = key.String()
		if err := config.PersistPrivateKey(cfg.SourcePath(), key.String()); err != nil {
			log.Printf("警告: 私钥已生成但无法写回配置（%v）；重启后公钥会变，客户端需要重新配置", err)
		} else {
			log.Printf("已生成 WireGuard 私钥并写回 %s", cfg.SourcePath())
		}
	}
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

// cmdStatus 查看状态。--check 让链路不在 up 时以非 0 退出，给巡检脚本用。
func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	configPath := fs.String("config", "", "配置文件路径")
	check := fs.Bool("check", false, "链路不在 up 状态时以非 0 退出（给巡检脚本用）")
	if err := parseNoPositional(fs, args); err != nil {
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
	resp, err := call(endpoint, req, 30*time.Second)
	if err != nil {
		return err
	}
	fmt.Println(resp.Message)
	if resp.Code != ipc.CodeOK {
		return fmt.Errorf("链路不在正常状态")
	}
	return nil
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

// boolArg 把布尔值编成 IPC 的固定位置参数（见 ipc 包的说明）。
func boolArg(name string, v bool) string {
	if v {
		return name + "=1"
	}
	return name + "=0"
}
