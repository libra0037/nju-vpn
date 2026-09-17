package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/libra0037/nju-vpn/internal/config"
	"github.com/libra0037/nju-vpn/internal/ipc"
	"github.com/libra0037/nju-vpn/internal/service"
	"golang.org/x/term"
)

// errStateUnknown 表示服务进程应答了，但答不出状态。
//
// 最可能的成因是命令行与服务进程来自不同版本（端点按配置路径派生，旧进程
// 还占着那个端点）。
var errStateUnknown = errors.New("服务进程没有回报状态")

// clientConfig 是命令行客户端需要的配置。
//
// 显式指定的配置文件读不出来时直接失败：端点按配置文件路径派生，此时既算
// 不出端点，回落默认值又会打到另一个实例上——stop 与 restart 会误伤别人的
// 服务进程，比"命令用不了"糟得多。
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
	// 起不来，命令会以"服务进程是否在运行"收场。
	fmt.Fprintf(os.Stderr, "%s: 配置 %s 不可用: %v（按默认路径的端点继续）\n", prog, config.DefaultPath(), err)
	fallback := &config.Config{}
	fallback.SetSourcePath(config.DefaultPath())
	return fallback, nil
}

// call 向服务进程发一条请求并返回响应。
//
// 带超时：服务进程可能在等短信验证码、或正在退避重连，没有超时的客户端会
// 一直挂着，而用户看不出发生了什么。
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
// 显式配置了 ipc.endpoint 就用它；否则按配置文件的路径派生。后者是多实例
// 互不打架的关键：同一台机器上的每个实例各有一份配置文件，端点自然互不
// 相同（见 ipc.EndpointFor）。规则只有一份，在 ipc 包里——服务进程算实例
// 身份时用的是同一个函数。
func endpointOf(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
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
// 用专门的 state 命令而不是从 status 的显示文本里切第一段：那行是给人看
// 的，格式一改，判断就静默失效（而按文本写的测试还会继续通过）。
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

// runCommand 是那些"只发一条请求、没有位置参数"的命令的公共实现。
//
// timeout 由命令自己给：一次授信终端操作可能要登录一次（含短信），超时给
// 得跟 start 一样宽。
func runCommand(name string, args []string, req ipc.Request, timeout time.Duration) error {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	configPath := fs.String("config", "", "配置文件路径")
	if err := parseNoPositional(fs, args); err != nil {
		return err
	}
	endpoint, err := endpointFor(*configPath)
	if err != nil {
		return err
	}
	resp, err := call(endpoint, req, timeout)
	if err != nil {
		return err
	}
	return finish(endpoint, resp)
}

// maxCodeAttempts 是一次流程里最多让用户输几次验证码。
const maxCodeAttempts = 3

// finish 处理一条可能停在验证码上的响应。
//
// 428 表示服务端在等验证码：把提示打出来、把用户输的码送回去，然后接着看
// 结果。验证码输错时服务进程回 400 但会话还等着，这时再给一次机会——用户
// 手一抖不该让整条流程从头再来一遍（重新登录、重新发短信）。
func finish(endpoint string, resp ipc.Response) error {
	for attempts := 0; ; {
		fmt.Println(resp.Message)

		switch {
		case resp.Code == ipc.CodeOK:
			return nil
		case resp.Code == ipc.CodeAuthRequired:
			// 需要用户输验证码，走下面的提示。
		case resp.Code == ipc.CodeBadRequest && attempts > 0 && awaitingCode(endpoint):
			// 已经输过一次验证码又被拒：多半是码不对，而服务端还等着。
		default:
			return fmt.Errorf("服务进程返回 %d: %s", resp.Code, resp.Message)
		}

		if attempts >= maxCodeAttempts {
			return fmt.Errorf("验证码连续 %d 次没有通过，已放弃：重新执行 %s start 可以再试一次", attempts, prog)
		}
		code, err := promptCode()
		if err != nil {
			return err
		}
		if code == "" {
			return errors.New("验证码为空")
		}
		attempts++

		if resp, err = call(endpoint, ipc.Request{Command: ipc.CmdAuth, Args: []string{code}}, startTimeout); err != nil {
			return err
		}
	}
}

// awaitingCode 报告服务进程是不是还在等验证码。
func awaitingCode(endpoint string) bool {
	state, err := serviceState(endpoint)
	return err == nil && state == string(service.StateAuthPending)
}

// passwordFor 决定本次要不要现问口令。
//
// 配置里写了口令就用配置里的（服务进程自己会读）；没写就现问一遍，只经本地
// 套接字传过去。stdin 是管道时也照读，便于脚本一次喂口令和验证码。
//
// 隧道已经在跑时不问：这条路径上的操作（start 幂等、授信终端操作复用当前
// 会话）都不需要口令，而看门狗式脚本每隔几分钟敲一次 start，每次都停在口令
// 提示上等于让脚本永远失败——stdin 是 /dev/null 时更是直接以一句裸 EOF 收场。
func passwordFor(cfg *config.Config, endpoint string) (string, error) {
	if cfg == nil || cfg.Password != "" {
		return "", nil
	}
	if state, err := serviceState(endpoint); err == nil && state == string(service.StateUp) {
		return "", nil
	}
	password, err := promptSecret("请输入校园网口令: ")
	if err != nil {
		if errors.Is(err, io.EOF) {
			return "", errors.New("读不到口令，且标准输入已经结束（非交互运行？）：" +
				"请在配置文件的 password 里写入口令，或改用交互式终端运行")
		}
		return "", err
	}
	return strings.TrimSpace(password), nil
}

// stdinReader 是复用的标准输入读取器。
//
// 管道里可能一次喂了多行（先口令后验证码），每次新建 bufio.Reader 会把多读
// 到的那些字节一起丢掉。
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
		if errors.Is(err, io.EOF) {
			return "", errors.New("读不到验证码，且标准输入已经结束（非交互运行？）")
		}
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
