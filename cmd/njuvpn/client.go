package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/libra0037/nju-vpn/internal/config"
	"github.com/libra0037/nju-vpn/internal/ipc"
	"github.com/libra0037/nju-vpn/internal/service"
	"golang.org/x/term"
)

// clientConfig 是命令行客户端需要的配置：只有 IPC 端点。
//
// 显式指定的配置文件读不出来时直接失败：端点按配置文件路径派生，此时既
// 算不出端点，回落默认值又会打到另一个实例上——stop 与 restart 会误伤
// 别人的服务进程，比"命令用不了"糟得多。
func clientConfig(configPath string) (*config.Config, error) {
	cfg, err := config.LoadForClient(configPath)
	if err == nil {
		return cfg, nil
	}
	if configPath != "" {
		return nil, fmt.Errorf("无法加载配置 %s: %w", configPath, err)
	}
	// 没显式指定路径时退一步：路径还是默认路径，只是内容读不出来或校验
	// 不过。端点只依赖路径，仍然算得出来；服务进程若也是这个情形，它同样
	// 起不来，命令会以"服务是否在运行"收场。
	fmt.Fprintf(os.Stderr, "%s: 配置 %s 不可用: %v（按默认路径的端点继续）\n", prog, config.DefaultPath(), err)
	fallback := &config.Config{}
	fallback.SetSourcePath(config.DefaultPath())
	return fallback, nil
}

// call 向服务进程发一条请求并返回响应。
//
// 带超时：服务进程可能在等短信验证码、或正在退避重试，
// 没有超时的客户端会一直挂着，而用户看不出发生了什么。
func call(endpoint string, req ipc.Request, timeout time.Duration) (ipc.Response, error) {
	conn, err := ipc.Dial(endpoint)
	if err != nil {
		return ipc.Response{}, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return ipc.Response{}, err
	}

	if err := ipc.WriteRequest(conn, req); err != nil {
		return ipc.Response{}, fmt.Errorf("发送请求: %w", err)
	}
	resp, err := ipc.ReadResponse(bufio.NewReader(conn))
	if err != nil {
		return ipc.Response{}, fmt.Errorf("读取响应: %w", err)
	}
	return resp, nil
}

// endpointOf 解析出 IPC 端点。
//
// 显式配置了 ipc.endpoint 就用它；否则按配置文件的路径派生。后者是
// 多实例互不打架的关键：同一台机器上的每个实例各有一份配置文件，
// 端点自然互不相同（见 ipc.EndpointFor）。
func endpointOf(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	// 规则只有一份，在 ipc 包里：服务进程算实例身份时用的是同一个函数。
	return ipc.ResolveEndpoint(cfg.IPC.Endpoint, cfg.SourcePath())
}

// endpointFor 是 clientConfig 加 endpointOf 的组合，供各命令使用。
func endpointFor(configPath string) (string, error) {
	cfg, err := clientConfig(configPath)
	if err != nil {
		return "", err
	}
	return endpointOf(cfg), nil
}

// serviceState 问服务进程当前处在什么状态。
//
// 用专门的 state 命令而不是从 status 的显示文本里切第一段：那行是给人看的，
// 格式一改，判断就静默失效（而按文本写的测试还会继续通过）。
func serviceState(endpoint string) (string, error) {
	resp, err := call(endpoint, ipc.Request{Command: ipc.CmdState}, 5*time.Second)
	if err != nil {
		return "", err
	}
	if resp.Code != ipc.CodeOK {
		return "", fmt.Errorf("%w: %d %s", errStateUnknown, resp.Code, resp.Message)
	}
	return strings.TrimSpace(resp.Message), nil
}

// errStateUnknown 表示服务进程应答了，但答不出状态。
//
// 最可能的成因是命令行与服务进程来自不同版本（端点按配置路径派生，旧进程
// 还占着那个端点）。
var errStateUnknown = errors.New("服务进程没有回报状态")

// ensureProbeIsSafe 在本机持有会话时拦一下 probe。
//
// probe 会完整登录一次，占掉该账号唯一的会话名额：正在跑的隧道会被服务端
// 踢下线（同一账号只允许一条会话），短信模式下还要再花一条验证码。
// 只是想把某个会话登掉的话，用 probe -logout -twf-id 就够。
func ensureProbeIsSafe(cfg *config.Config) error {
	state, err := serviceState(endpointOf(cfg))
	switch {
	case err == nil:
	case errors.Is(err, errStateUnknown):
		// 问不出"有没有会话"时保守拦住：拦错了只是让用户加 -force，
		// 放过则会踢掉正在跑的隧道，短信模式下还白花一条验证码。
		return fmt.Errorf("无法确认本机服务进程的状态（%v）：probe 可能另开一个会话，"+
			"把正在跑的隧道踢下线；先 njuvpn restart 让两边版本一致，或加 -force 继续", err)
	default:
		return nil // 服务进程没在跑，随便探
	}
	switch state {
	case string(service.StateIdle), string(service.StateError):
		// 只有这两种状态是"本机没有会话"。
		return nil
	}
	// 反过来列举放行状态，而不是列举要拦的状态：登录中（logging_in）与
	// 建承载中（connecting）都会完整登录一次，以前它们不在黑名单里，
	// probe 会把本机正在进行的 start 踢掉，短信模式下还多花一条验证码。
	return fmt.Errorf("本机服务进程正持有会话（%s）：probe 会另开一个会话把它踢下线"+
		"（同一账号只允许一条会话，短信模式下还会多花一条验证码）；"+
		"先 njuvpn stop，或加 -force 继续", state)
}

// runCommand 是 stop 与 wg-stats 的公共实现：只发一条请求，不接受位置参数。
//
// 退出码语义直接由响应状态码决定，不依赖提示文案：
// 200 算成功，其余算失败。
func runCommand(name string, args []string, req ipc.Request, timeout time.Duration) error {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	configPath := fs.String("config", "", "配置文件路径")
	if _, err := parseInterleaved(fs, args); err != nil {
		return err
	}
	endpoint, err := endpointFor(*configPath)
	if err != nil {
		return err
	}
	return runAt(endpoint, req, timeout)
}

// runAt 向指定端点发一条请求，并按响应状态码决定退出码。
//
// 428（需要验证码）只由 start / auth 产生，而它们不走这里，所以这里
// 没有那条分支。
func runAt(endpoint string, req ipc.Request, timeout time.Duration) error {
	resp, err := call(endpoint, req, timeout)
	if err != nil {
		return err
	}
	fmt.Println(resp.Message)

	switch resp.Code {
	case ipc.CodeOK:
		return nil
	default:
		return fmt.Errorf("服务进程返回 %d", resp.Code)
	}
}

// stdinReader 是复用的标准输入读取器。
//
// 管道里可能一次喂了多行（先口令后验证码），每次新建 bufio.Reader 会把
// 多读到的那些字节一起丢掉。
var stdinReader *bufio.Reader

// readStdinLine 读一行标准输入并去掉行尾。
func readStdinLine() (string, error) {
	if stdinReader == nil {
		stdinReader = bufio.NewReader(os.Stdin)
	}
	line, err := stdinReader.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// promptCode 从终端读验证码。
//
// 验证码保持回显：它是一次性的，而且用户需要看到自己敲了几位。
func promptCode() (string, error) {
	fmt.Fprint(os.Stderr, "请输入验证码: ")
	code, err := readStdinLine()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(code), nil
}

// promptSecret 从终端读一行不回显的输入（口令）。
//
// 终端上用 x/term 关掉回显；stdin 不是终端时（管道、脚本）按普通行读——
// 那种场景本来就没有回显可关，而 ReadPassword 在非终端上会直接报错。
func promptSecret(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return readStdinLine()
	}
	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
