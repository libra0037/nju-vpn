package service

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/libra0037/nju-vpn/internal/ipc"
	"github.com/libra0037/nju-vpn/internal/vpn"
)

const (
	// idleTimeout 是客户端连接的空闲上限。超过它没有任何请求就断开，
	// 免得一个挂死的客户端长期占着文件描述符。
	idleTimeout = 60 * time.Second
	// writeTimeout 限制一次写响应的时间。
	writeTimeout = 15 * time.Second
	// shutdownWaitTimeout 是退出时等待在处理的请求写完响应的上限。
	shutdownWaitTimeout = 3 * time.Second
)

// Server 在本地端点上提供服务，把 IPC 请求转成对 Service 的调用。
type Server struct {
	svc      *Service
	listener net.Listener

	closing  chan struct{}
	once     sync.Once
	quit     chan struct{}
	quitOnce sync.Once
	wg       sync.WaitGroup
}

// NewServer 构造服务端。
func NewServer(svc *Service, listener net.Listener) *Server {
	return &Server{
		svc:      svc,
		listener: listener,
		closing:  make(chan struct{}),
		quit:     make(chan struct{}),
	}
}

// Shutdown 停止接受新连接。处理中的连接会自然结束，不在退出路径上等待。
func (s *Server) Shutdown() {
	s.once.Do(func() {
		close(s.closing)
		s.listener.Close()
	})
}

// isClosing 报告服务是否正在关闭。
func (s *Server) isClosing() bool {
	select {
	case <-s.closing:
		return true
	default:
		return false
	}
}

// Done 在收到 shutdown 命令时关闭；系统信号不走这里。
func (s *Server) Done() <-chan struct{} { return s.quit }

// requestShutdown 记录"客户端要求退出"。真正的收尾在 RunServer 里做
// （它会返回，让调用方执行登出）。
func (s *Server) requestShutdown() { s.quitOnce.Do(func() { close(s.quit) }) }

// Serve 开始接受连接，直到 listener 被关闭。
func (s *Server) Serve() error {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(conn)
		}()
	}
}

// Wait 等待在处理的连接结束，最多等 timeout。
//
// 退出时不等待会把"已经成功、只差回包"的请求截断，客户端看到的是连接断开。
func (s *Server) Wait(timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		log.Printf("仍有请求在处理，等待超过 %s，继续退出", timeout)
	}
}

// handle 处理一条客户端连接。
func (s *Server) handle(conn net.Conn) {
	defer conn.Close()

	// panic 边界：一个畸形请求不该带走整个服务进程——服务端的会话
	// 还开着，进程直接死掉就没人登出了。
	defer func() {
		if r := recover(); r != nil {
			log.Printf("处理 IPC 请求时发生内部错误: %v\n%s", r, debug.Stack())
		}
	}()

	reader := bufio.NewReader(conn)
	for {
		// 退出过程中不再接受新请求，避免刚登出又被叫起来建隧道。
		if s.isClosing() {
			return
		}
		if err := conn.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
			return
		}
		req, err := ipc.ReadRequest(reader)
		if err != nil {
			return
		}

		resp := s.dispatch(req)
		if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
			return
		}
		if err := ipc.WriteResponse(conn, resp); err != nil {
			return
		}
	}
}

// dispatch 把一条请求映射成一个响应。
func (s *Server) dispatch(req ipc.Request) ipc.Response {
	switch req.Command {
	case ipc.CmdPing:
		// 探活顺带报出身份：同机多实例时，"这台机器上跑着谁"是排查的
		// 第一个问题，而 ping 是唯一永远可用的命令。
		return ipc.Response{Code: ipc.CodeOK, Message: "pong " + identityText(s.svc.Identity())}

	case ipc.CmdShutdown:
		// 先安排退出再回包（回包由 handle 写到这条连接上）：
		// 客户端要能确认命令被接受，而不是看到一个断掉的连接。
		s.requestShutdown()
		return ipc.Response{Code: ipc.CodeOK, Message: "服务进程正在退出"}

	case ipc.CmdStatus:
		st := s.svc.Status()
		// `status -check` 给巡检脚本用：隧道不在 up 时以非 0 退出，
		// 而不是把"进程活着"当成"链路正常"。
		//
		// 正在退避重连时也算不正常：状态还是 up（隧道对象还在），
		// 但链路是断的。
		if len(req.Args) > 0 && req.Args[0] == "check" && (st.State != StateUp || st.Retrying) {
			return ipc.Response{Code: ipc.CodeRejected, Message: statusLine(st)}
		}
		return ipc.Response{Code: ipc.CodeOK, Message: statusLine(st)}

	case ipc.CmdState:
		// 只回报状态名，不做任何修饰：调用方拿它做判断，
		// 不必去解析给人看的那行文本。
		return ipc.Response{Code: ipc.CodeOK, Message: string(s.svc.Status().State)}

	case ipc.CmdSetProxy:
		if len(req.Args) == 0 {
			return ipc.Response{Code: ipc.CodeBadRequest, Message: "用法: set-proxy <地址>"}
		}
		proxy, err := ipc.DecodeSecret(req.Args[0])
		if err != nil {
			return ipc.Response{Code: ipc.CodeBadRequest, Message: err.Error()}
		}
		if err := s.svc.SetProxy(proxy); err != nil {
			return ipc.Response{Code: ipc.CodeServerError, Message: err.Error()}
		}
		return ipc.Response{Code: ipc.CodeOK, Message: "出站代理已更新"}

	case ipc.CmdStart:
		// 已经建好时再敲一次 start 是常见操作（脚本巡检也会这么写），
		// 按成功处理，别报成 409 让看门狗一直以为出事了。
		if s.svc.Status().State == StateUp {
			return ipc.Response{Code: ipc.CodeOK, Message: "隧道已在运行"}
		}
		password, err := passwordArg(req.Args)
		if err != nil {
			return ipc.Response{Code: ipc.CodeBadRequest, Message: err.Error()}
		}
		err = s.svc.StartWithPassword(password)
		switch {
		case err == nil:
			return ipc.Response{Code: ipc.CodeOK, Message: "隧道已建立"}
		case errors.Is(err, ErrAuthRequired):
			return ipc.Response{Code: ipc.CodeAuthRequired, Message: s.svc.Status().Detail}
		case errors.Is(err, ErrBadState):
			// 已经在跑时又敲一次 start 是常见操作，不该报成服务端故障。
			return ipc.Response{Code: ipc.CodeRejected, Message: err.Error()}
		case errors.Is(err, ErrStopRequested):
			// 排队期间用户已经敲了 stop，这条 start 没有执行。
			return ipc.Response{Code: ipc.CodeRejected, Message: err.Error()}
		case errors.Is(err, ErrShuttingDown):
			return ipc.Response{Code: ipc.CodeRejected, Message: err.Error()}
		default:
			return ipc.Response{Code: ipc.CodeServerError, Message: err.Error()}
		}

	case ipc.CmdAuth:
		if len(req.Args) == 0 {
			return ipc.Response{Code: ipc.CodeBadRequest, Message: "用法: auth <验证码>"}
		}
		// 验证码可能被拆成多个参数（用户敲了空格），拼回去再用。
		code := strings.TrimSpace(strings.Join(req.Args, ""))
		err := s.svc.Auth(code)
		switch {
		case err == nil:
			return ipc.Response{Code: ipc.CodeOK, Message: "验证成功，隧道已建立"}
		case errors.Is(err, ErrAuthRequired):
			return ipc.Response{Code: ipc.CodeAuthRequired, Message: s.svc.Status().Detail}
		case errors.Is(err, ErrShuttingDown):
			return ipc.Response{Code: ipc.CodeRejected, Message: err.Error()}
		case errors.Is(err, ErrBadState):
			// 当前状态不需要验证码：用法问题，不是服务端故障。
			return ipc.Response{Code: ipc.CodeRejected, Message: err.Error()}
		case errors.Is(err, ErrEmptyCode), vpn.IsAuthCodeError(err):
			// 验证码错误属于客户端输入问题，缺验证码同理。
			return ipc.Response{Code: ipc.CodeBadRequest, Message: err.Error()}
		default:
			// 其余（网络错误、承载启动失败、内部错误）是服务端这一侧的问题：
			// 以前一律回 400，脚本会把"服务端故障"当成"我验证码敲错了"。
			return ipc.Response{Code: ipc.CodeServerError, Message: err.Error()}
		}

	case ipc.CmdSetPeer:
		if len(req.Args) == 0 {
			return ipc.Response{Code: ipc.CodeBadRequest, Message: "用法: wg-peer <客户端公钥>"}
		}
		key := strings.TrimSpace(strings.Join(req.Args, ""))
		if err := s.svc.SetPeer(key); err != nil {
			return ipc.Response{Code: ipc.CodeBadRequest, Message: err.Error()}
		}
		return ipc.Response{Code: ipc.CodeOK, Message: "已更新 WireGuard 接入公钥"}

	case ipc.CmdWGStats:
		stats, err := s.svc.WireGuardStats()
		if err != nil {
			return ipc.Response{Code: ipc.CodeRejected, Message: err.Error()}
		}
		if len(stats) == 0 {
			return ipc.Response{Code: ipc.CodeOK, Message: "承载层没有接入的 peer"}
		}
		parts := make([]string, 0, len(stats))
		for _, st := range stats {
			line := fmt.Sprintf("peer %s: 收 %d 字节 / 发 %d 字节", st.PublicKey, st.RxBytes, st.TxBytes)
			if st.LastHandshake.IsZero() {
				line += "，尚未握手"
			} else {
				line += fmt.Sprintf("，最近握手 %s", st.LastHandshake.Format("15:04:05"))
			}
			parts = append(parts, line)
		}
		return ipc.Response{Code: ipc.CodeOK, Message: strings.Join(parts, " | ")}

	case ipc.CmdStop:
		err := s.svc.Stop()
		switch {
		case err == nil:
			// 说明文字取自状态：登出没成功时会在这里带出来，
			// 用户才知道服务端名额可能还占着、下次 start 可能被拒。
			msg := "隧道已断开"
			if d := s.svc.Status().Detail; d != "" {
				msg = d
			}
			return ipc.Response{Code: ipc.CodeOK, Message: msg}
		case errors.Is(err, ErrNotRunning):
			// 已经处在"隧道没在跑"这个状态了：stop 想要的结果成立，就报成功，
			// 否则脚本里一句再普通不过的 `njuvpn stop` 会因为"已经停了"失败。
			// 文案仍与真断开分开，用户看得出这次什么都没做。
			return ipc.Response{Code: ipc.CodeOK, Message: "隧道本来就没有运行"}
		case errors.Is(err, ErrShuttingDown):
			return ipc.Response{Code: ipc.CodeRejected, Message: err.Error()}
		default:
			return ipc.Response{Code: ipc.CodeServerError, Message: err.Error()}
		}

	default:
		return ipc.Response{Code: ipc.CodeBadRequest, Message: "未知命令: " + req.Command}
	}
}

// passwordArg 解出请求里携带的口令。
//
// 参数缺省表示沿用服务进程内存里已有的口令（配置文件里的那份，或上一次
// start 带来的那份）；带了就是 base64 编码的本次输入。
func passwordArg(args []string) (string, error) {
	if len(args) == 0 {
		return "", nil
	}
	return ipc.DecodeSecret(args[0])
}

// statusLine 把状态拼成一行文本。
func statusLine(st Status) string {
	msg := string(st.State)
	if st.Retrying {
		msg += "（链路已断开，正在重连）"
	}
	if st.Detail != "" {
		msg += " | " + st.Detail
	}
	if st.ClientIP != "" {
		msg += " | 校园网地址 " + st.ClientIP
	}
	if st.PeerIP != "" {
		msg += " | peer " + st.PeerIP
	}
	if !st.Since.IsZero() {
		msg += fmt.Sprintf(" | %s 起", st.Since.Format("15:04:05"))
	}
	if id := identityText(st.Identity); id != "" {
		msg += " | " + id
	}
	return msg
}

// identityText 把实例身份拼成一段文本，供 ping 与 status 共用。
//
// 只包含 PID、账号、配置路径与端点——都不算秘密，能连上本地端点的人
// 本来就看得到这些文件。
func identityText(id Identity) string {
	parts := []string{fmt.Sprintf("pid=%d", id.PID)}
	if id.Username != "" {
		parts = append(parts, "账号="+id.Username)
	}
	if id.ConfigPath != "" {
		parts = append(parts, "配置="+id.ConfigPath)
	}
	if id.Endpoint != "" {
		parts = append(parts, "端点="+id.Endpoint)
	}
	return strings.Join(parts, " ")
}

// RunServer 是服务进程的入口：监听本地端点并处理请求。
// 返回时说明服务已经停止。
func RunServer(svc *Service, endpoint string) error {
	// 端点由调用方按配置文件的身份解析好（见 ipc.EndpointFor）：
	// 这里不再有"默认端点"这个退路，否则配置读不出来时会静默地
	// 和另一个实例抢同一个端点。
	if endpoint == "" {
		return ipc.ErrEmptyEndpoint
	}
	ln, err := ipc.Listen(endpoint)
	if err != nil {
		return err
	}
	log.Printf("服务已启动，监听 %s", endpoint)

	srv := NewServer(svc, ln)

	// 两条退出路径：系统信号（Ctrl-C / systemd / 任务计划程序），
	// 以及 shutdown 命令（njuvpn restart 用的就是它）。
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case sig := <-signals:
			log.Printf("收到信号 %v，准备退出", sig)
		case <-srv.Done():
			log.Printf("收到 shutdown 命令，准备退出")
		case <-svc.Done():
			log.Printf("服务对象已收尾，准备退出")
		}
		// 先收尾（含登出）再关监听：CLI 的 restart 用"端点不再响应"判断旧
		// 进程已经退干净。端点若先消失，新进程会和还没发完的登出抢同一个
		// 账号的名额（服务端只允许一条会话）。
		svc.Close()
		srv.Shutdown()
	}()
	// 故意不 signal.Stop：收尾（登出）由调用方在 Serve 返回之后做，
	// 这段时间里第二个 Ctrl-C 必须被吞掉而不是立刻终止进程——默认动作
	// 会把登出请求打断，服务端名额要等它自己超时才释放。

	err = srv.Serve()
	// Serve 返回说明监听已经关闭；这里再收一次尾（Close 幂等），然后等
	// 在处理的请求写完响应。
	svc.Close()
	srv.Shutdown()
	// 等在处理的请求写完响应再返回：调用方随后就会登出并退出。
	srv.Wait(shutdownWaitTimeout)
	return err
}
