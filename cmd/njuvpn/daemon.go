package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/libra0037/nju-vpn/internal/config"
	"github.com/libra0037/nju-vpn/internal/ipc"
)

const (
	// serviceStartTimeout 是等待刚拉起的服务进程就绪的上限。启动只做配置
	// 加载与私钥生成（首次运行时），通常远快于这个值。
	serviceStartTimeout = 10 * time.Second
	// serviceStopTimeout 是等待服务进程退出的上限（含一次登出请求）。
	//
	// 服务进程是先登出、再关监听（这样"端点不再响应"就等于"会话已释放"），
	// 所以这个上限要能覆盖一次登出：登出自身有超时，加上收尾的等待。
	serviceStopTimeout = 30 * time.Second
	// pingTimeout 是单次探活的超时。
	pingTimeout = 500 * time.Millisecond
)

// serviceLogPath 让服务进程的日志落在配置文件旁边。
//
// 被命令行拉起的服务进程没有控制台，日志必须有地方去；放在配置旁边的好处
// 是"启动失败"时用户知道该看哪个文件。文件名带配置名：同一目录下放多份配置
// 时不该共用一份日志，多实例的行交错在一起，排查时容易张冠李戴。
func serviceLogPath(configPath string) string {
	path := configPath
	if path == "" {
		path = config.DefaultPath()
	}
	return filepath.Join(filepath.Dir(path), logFileName(path))
}

// logFileName 给日志文件取名：njuvpn-<实例标识>-<配置名>.log。
//
// 配置名里只保留可移植的字符，剩下的换成下划线：这个值来自命令行给的路径，
// 不该把路径分隔符之类的东西带进文件名。
//
// 光靠清洗过的配置名区分不开实例：a b.yaml 与 a_b.yaml 清洗后同名，而这两
// 个文件名正是要避免交错的那种情况。实例标识由路径的哈希派生，加到名字里
// 就唯一了。
func logFileName(configPath string) string {
	base := strings.TrimSuffix(filepath.Base(configPath), filepath.Ext(configPath))
	if base == "" || base == "." {
		base = "default"
	}
	var b strings.Builder
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return "njuvpn-" + ipc.InstanceTag(configPath) + "-" + b.String() + ".log"
}

// pingService 探活：连得上并得到 pong 才算服务进程在运行。
//
// 超时单独给一个很小的值：探活失败是常态（进程没起），不该让调用方等太久。
func pingService(endpoint string) error {
	resp, err := call(endpoint, ipc.Request{Command: ipc.CmdPing}, pingTimeout)
	if err != nil {
		return err
	}
	if resp.Code != ipc.CodeOK {
		return fmt.Errorf("服务进程返回 %d: %s", resp.Code, resp.Message)
	}
	return nil
}

// ensureService 确保服务进程在运行：连不上就拉起一个。
//
// 服务进程由命令行按需拉起，而不是装成系统服务——它不需要任何特权，也只在
// 你要用的时候才有存在意义。
func ensureService(configPath string) error {
	endpoint, err := endpointFor(configPath)
	if err != nil {
		return err
	}
	if err := pingService(endpoint); err == nil {
		return nil
	} else if !errors.Is(err, ipc.ErrNotRunning) {
		return err
	}

	logPath := serviceLogPath(configPath)
	exited, err := spawnService(configPath, logPath)
	if err != nil {
		return err
	}
	log.Printf("已拉起服务进程（日志: %s）", logPath)

	return waitServiceReady(endpoint, logPath, exited, serviceStartTimeout)
}

// waitServiceReady 等到服务进程开始应答，或者在它提前退出时立刻报错。
//
// 两个信号要一起等：只轮询端点时，"子进程起来就崩"（配置写错、端口被占
// 之类）会一直等到超时，而原因其实已经写在日志里了。
func waitServiceReady(endpoint, logPath string, exited <-chan error, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if exited != nil {
			select {
			case err := <-exited:
				exited = nil
				// 我们拉起的子进程退了，但端点可能已经有另一个服务进程在应答：
				// 并发调用（看门狗与人工同时执行）里只有一个能占住端点，输的
				// 那个立刻退出，赢的那个此刻正在就绪。直接报“启动后立即退出”
				// 会给巡检脚本一个假警报，所以先给赢家一点时间。
				if pumpErr := pingUntil(endpoint, daemonAdoptGrace); pumpErr == nil {
					log.Printf("服务进程已由另一个调用拉起（本次拉起的子进程退出: %v）", err)
					return nil
				}
				if err == nil {
					err = errors.New("退出码 0")
				}
				return fmt.Errorf("服务进程启动后立即退出（%v）%s", err, logTail(logPath))
			default:
			}
		}
		if err := pingService(endpoint); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("服务进程在 %s 内没有就绪%s", timeout, logTail(logPath))
}

// daemonAdoptGrace 是“我们拉起的子进程退出后，再等端点一小会儿”的上限。
//
// 只要够盖住赢家从绑定端点到能应答的那一小段，不需要更多：真正起不来的
// 情况（配置写错、端口被占）等再久也不会应答。
const daemonAdoptGrace = 2 * time.Second

// pingUntil 在 give 时间内轮询端点，应答了就返回 nil。
func pingUntil(endpoint string, give time.Duration) error {
	deadline := time.Now().Add(give)
	var last error
	for {
		if last = pingService(endpoint); last == nil {
			return nil
		}
		if !time.Now().Before(deadline) {
			return last
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// spawnService 以脱离终端的方式启动服务进程。
//
// 返回的 channel 在子进程退出时收到它的退出状态：就绪轮询要同时盯着它，
// 否则子进程立刻退出时用户只能干等超时，再被指去翻日志。
func spawnService(configPath, logPath string) (<-chan error, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("定位可执行文件: %w", err)
	}

	args := []string{"run"}
	if configPath != "" {
		args = append(args, "-config", configPath)
	}

	logFile, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("打开服务进程日志 %s: %w", logPath, err)
	}

	cmd := exec.Command(exe, args...)
	cmd.Env = append(os.Environ(), daemonLogEnv+"="+logPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Stdin = nil
	cmd.SysProcAttr = detachedProcAttr()
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return nil, fmt.Errorf("启动服务进程: %w", err)
	}
	// 不等它：服务进程要在命令行退出之后继续跑。
	exited := make(chan error, 1)
	go func() {
		defer logFile.Close()
		exited <- cmd.Wait()
	}()
	return exited, nil
}

// logTail 取日志文件的最后几行，附在"服务进程没起来"这类错误后面。
//
// 只读尾部：日志不做轮转，跑久了的文件不该整个读进内存。
func logTail(path string) string {
	const maxBytes = 8 << 10
	const maxLines = 15
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return ""
	}
	start := fi.Size() - maxBytes
	if start < 0 {
		start = 0
	}
	buf := make([]byte, fi.Size()-start)
	if _, err := f.ReadAt(buf, start); err != nil && !errors.Is(err, io.EOF) {
		return ""
	}
	body := string(buf)
	if start > 0 {
		// 从中间截断时第一行可能只有半截，丢掉。
		if i := strings.IndexByte(body, '\n'); i >= 0 {
			body = body[i+1:]
		}
	}
	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		return ""
	}

	var b strings.Builder
	b.WriteString("\n服务进程日志的最后几行（" + path + "）：")
	for _, line := range lines {
		b.WriteString("\n  " + line)
	}
	return b.String()
}

// shutdownService 请服务进程收尾退出（它会先登出再退出）。
func shutdownService(endpoint string) error {
	resp, err := call(endpoint, ipc.Request{Command: ipc.CmdShutdown}, serviceStopTimeout)
	if err != nil {
		return err
	}
	if resp.Code != ipc.CodeOK {
		return fmt.Errorf("服务进程返回 %d: %s", resp.Code, resp.Message)
	}
	fmt.Println(resp.Message)
	return nil
}

// waitServiceGone 等到服务进程真的退出（端点不再响应）。
func waitServiceGone(endpoint string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := pingService(endpoint); err != nil {
			if errors.Is(err, ipc.ErrNotRunning) {
				return nil
			}
			// shutdown 已获确认后，正在接入的连接可能被关闭。仍须再次确认
			// 端点无人监听；重置连接本身不能证明旧进程已经退出。
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, syscall.ECONNRESET) && !errors.Is(err, syscall.EPIPE) {
				return err
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("服务进程在 %s 内没有退出（可能卡在登出）", timeout)
}
