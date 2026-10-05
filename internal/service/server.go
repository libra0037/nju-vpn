package service

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/libra0037/nju-vpn/internal/ipc"
	"github.com/libra0037/nju-vpn/internal/ztna"
)

const (
	// idleTimeout 是客户端连接的空闲上限。超过它没有任何请求就断开，
	// 免得一个挂死的客户端长期占着文件描述符。
	idleTimeout = 60 * time.Second
	// writeTimeout 限制一次写响应的时间。
	writeTimeout = 15 * time.Second
	// shutdownWaitTimeout 是退出时等待在处理的请求写完响应的上限。
	shutdownWaitTimeout = 3 * time.Second
	maxConnections      = 64
)

// Server 在本地端点上提供服务，把 IPC 请求转成对 Service 的调用。
type Server struct {
	svc      *Service
	listener net.Listener

	closing     chan struct{}
	once        sync.Once
	quit        chan struct{}
	quitOnce    sync.Once
	wg          sync.WaitGroup
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	// 编码与发送共用一个名额，包括客户端背压期间；普通请求不占用它。
	resourceReply chan struct{}
}

// NewServer 构造服务端。
func NewServer(svc *Service, listener net.Listener) *Server {
	return &Server{
		svc:           svc,
		listener:      listener,
		closing:       make(chan struct{}),
		quit:          make(chan struct{}),
		connections:   make(map[net.Conn]struct{}),
		resourceReply: make(chan struct{}, 1),
	}
}

// Shutdown 停止接受新连接。处理中的连接会自然结束，不在退出路径上等待。
func (s *Server) Shutdown() {
	s.once.Do(func() {
		close(s.closing)
		s.listener.Close()
		s.mu.Lock()
		for conn := range s.connections {
			_ = conn.SetReadDeadline(time.Now())
		}
		s.mu.Unlock()
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

		s.mu.Lock()
		if s.isClosing() || len(s.connections) >= maxConnections {
			s.mu.Unlock()
			conn.Close()
			continue
		}
		s.connections[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer func() { s.mu.Lock(); delete(s.connections, conn); s.mu.Unlock() }()
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
		s.mu.Lock()
		for conn := range s.connections {
			conn.Close()
		}
		s.mu.Unlock()
		<-done
	}
}

// handle 处理一条客户端连接。
func (s *Server) handle(conn net.Conn) {
	defer conn.Close()

	// panic 边界：一个畸形请求不该带走整个服务进程——服务端的会话还开着，
	// 进程直接死掉就没人登出了。
	defer func() {
		if recover() != nil {
			log.Printf("处理 IPC 请求时发生内部错误")
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
			// 超长行与畸形请求是"客户端写错了"，按协议回一条 400 再断开：
			// 调用方读到 0 字节 + EOF 时，与"服务进程已经退出"或"命令打到了
			// 别的实例"完全同形，也拿不到可重试的信号。正常断开（EOF）保持
			// 静默——那是客户端干完了活。
			if !errors.Is(err, io.EOF) {
				msg := "请求格式错误"
				if errors.Is(err, ipc.ErrLineTooLong) {
					msg = fmt.Sprintf("请求超过 %d 字节的长度上限", ipc.MaxLineBytes)
				}
				_ = s.writeResponse(conn, ipc.Response{Code: ipc.CodeBadRequest, Message: msg})
			}
			return
		}

		if err := s.reply(conn, req); err != nil {
			return
		}
	}
}

// reply 的名额覆盖资源编码到写完响应，限制大响应的总分配与等待数量。
func (s *Server) reply(conn net.Conn, req ipc.Request) error {
	if req.Command == ipc.CmdResources && len(req.Args) == 0 {
		select {
		case s.resourceReply <- struct{}{}:
			defer func() { <-s.resourceReply }()
		default:
			return s.writeResponse(conn, ipc.Response{
				Code: ipc.CodeRejected, Message: "资源查询正在进行，请稍后重试",
			})
		}
	}
	return s.writeResponse(conn, s.dispatch(req))
}

func (s *Server) writeResponse(conn net.Conn, resp ipc.Response) error {
	if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	return ipc.WriteResponse(conn, resp)
}

// dispatch 把一条请求映射成一个响应。
func (s *Server) dispatch(req ipc.Request) ipc.Response {
	switch req.Command {
	case ipc.CmdPing:
		// 探活顺带报出身份：同机多实例时，"这台机器上跑着谁"是排查的
		// 第一个问题，而 ping 是唯一永远可用的命令。
		return ipc.Response{Code: ipc.CodeOK, Message: "pong " + identityText(s.svc.Identity())}

	case ipc.CmdShutdown:
		// 先安排退出再回包（回包由 handle 写到这条连接上）：客户端要能
		// 确认命令被接受，而不是看到一个断掉的连接。
		s.requestShutdown()
		return ipc.Response{Code: ipc.CodeOK, Message: "服务进程正在退出"}

	case ipc.CmdState:
		// 只回报状态名，不做任何修饰：调用方拿它做判断，不必去解析给人
		// 看的那行文本。
		return ipc.Response{Code: ipc.CodeOK, Message: string(s.svc.Status().State)}

	case ipc.CmdStatus:
		jsonOutput := false
		for _, arg := range req.Args {
			switch {
			case arg == "json" && !jsonOutput:
				jsonOutput = true
			default:
				return ipc.Response{Code: ipc.CodeBadRequest, Message: "status 只接受一次 json"}
			}
		}
		st := s.svc.Status()
		message := statusLine(st)
		if jsonOutput {
			body, err := json.Marshal(st)
			if err != nil {
				return ipc.Response{Code: ipc.CodeServerError, Message: "状态快照编码失败"}
			}
			message = string(body)
		}
		// 输出格式不改变就绪判据；退避重连时对象虽在，链路仍未就绪。
		if st.State != StateUp || st.Retrying {
			return ipc.Response{Code: ipc.CodeRejected, Message: message}
		}
		return ipc.Response{Code: ipc.CodeOK, Message: message}

	case ipc.CmdResources:
		if len(req.Args) != 0 {
			return ipc.Response{Code: ipc.CodeBadRequest, Message: "resources 不接受参数"}
		}
		body, err := s.svc.ResourcesJSON(ipc.MaxLineBytes - len("200 \n"))
		if err != nil {
			if errors.Is(err, ztna.ErrResourceSnapshotTooLarge) {
				return ipc.Response{Code: ipc.CodeServerError, Message: fmt.Sprintf("资源列表超过 %d 字节的 IPC 响应上限", ipc.MaxLineBytes)}
			}
			return ipc.Response{Code: ipc.CodeRejected, Message: ztna.ErrResourcesUnavailable.Error()}
		}
		return ipc.Response{Code: ipc.CodeOK, Message: string(body)}

	case ipc.CmdStart:
		trust, err := ipc.BoolArg(ipc.Arg(req.Args, 0), "trust")
		if err != nil {
			return badRequest(err)
		}
		password, err := passwordArg(req.Args, 1)
		if err != nil {
			return badRequest(err)
		}
		// 已经建好时再敲一次 start 是常见操作（巡检脚本也会这么写），
		// 按成功处理，别报成 409 让看门狗一直以为出事了。带 --trust 时
		// 顺带确保授信——它同样是幂等的，而且复用正在跑的会话。
		if s.svc.Status().State == StateUp {
			msg := "隧道已在运行"
			if trust {
				if err := s.svc.Trust(""); err != nil {
					return s.errorResponse(err)
				}
				msg += "，" + s.svc.Status().Detail
			}
			return ipc.Response{Code: ipc.CodeOK, Message: msg}
		}
		if err := s.svc.Start(trust, password); err != nil {
			return s.errorResponse(err)
		}
		return ipc.Response{Code: ipc.CodeOK, Message: detailOr("隧道已建立", s.svc.Status().Detail)}

	case ipc.CmdAuth:
		// 验证码可能被拆成多个参数（用户敲了空格），拼回去再用。
		code := strings.TrimSpace(strings.Join(req.Args, ""))
		if err := s.svc.Auth(code); err != nil {
			return s.errorResponse(err)
		}
		return ipc.Response{Code: ipc.CodeOK, Message: detailOr("验证成功", s.svc.Status().Detail)}

	case ipc.CmdTrust:
		password, err := passwordArg(req.Args, 0)
		if err != nil {
			return badRequest(err)
		}
		if err := s.svc.Trust(password); err != nil {
			return s.errorResponse(err)
		}
		return ipc.Response{Code: ipc.CodeOK, Message: detailOr("已确认为授信终端", s.svc.Status().Detail)}

	case ipc.CmdUntrust:
		all, err := ipc.BoolArg(ipc.Arg(req.Args, 0), "all")
		if err != nil {
			return badRequest(err)
		}
		password, err := passwordArg(req.Args, 1)
		if err != nil {
			return badRequest(err)
		}
		if err := s.svc.Untrust(password, all); err != nil {
			return s.errorResponse(err)
		}
		return ipc.Response{Code: ipc.CodeOK, Message: detailOr("已解除授信", s.svc.Status().Detail)}

	case ipc.CmdStop:
		err := s.svc.Stop()
		switch {
		case err == nil:
			// 说明文字取自状态：登出没成功时会在这里带出来，用户才知道
			// 服务端名额可能还占着、下次 start 可能被拒。
			return ipc.Response{Code: ipc.CodeOK, Message: detailOr("隧道已断开", s.svc.Status().Detail)}
		case errors.Is(err, ErrNotRunning):
			// 已经处在"隧道没在跑"这个状态了：stop 想要的结果成立，就报成功，
			// 否则脚本里一句再普通不过的 njuvpn stop 会因为"已经停了"失败。
			// 文案仍与真断开分开，用户看得出这次什么都没做。
			return ipc.Response{Code: ipc.CodeOK, Message: "隧道本来就没有运行"}
		default:
			return s.errorResponse(err)
		}

	default:
		return ipc.Response{Code: ipc.CodeBadRequest, Message: "未知命令"}
	}
}

// errorResponse 把服务层的错误翻成响应。
//
// 状态码是契约：调用方按码分流（428 要验证码、4xx 是用法或输入问题、
// 5xx 是服务进程这一侧的问题），不去解析文案。
func (s *Server) errorResponse(err error) ipc.Response {
	switch {
	case errors.Is(err, ErrAuthRequired):
		// 428 不是错误：提示文字取自状态，那里写着"验证码发到哪了"。
		return ipc.Response{Code: ipc.CodeAuthRequired, Message: s.svc.Status().Detail}
	case errors.Is(err, ErrEmptyCode):
		return badRequest(err)
	case errors.Is(err, ErrMissingCredential):
		// 配置里没写账号、或没带上口令：用户得先去填配置/输入口令，
		// 不是服务进程出了故障。
		return badRequest(err)
	case errors.Is(err, ErrBadState), errors.Is(err, ErrNotRunning),
		errors.Is(err, ErrStopRequested), errors.Is(err, ErrShuttingDown):
		return ipc.Response{Code: ipc.CodeRejected, Message: err.Error()}
	}
	if _, ok := ztna.AsRejected(err); ok {
		// 口令或验证码不对：属于用户输入问题，不是服务端故障。
		return badRequest(err)
	}
	return ipc.Response{Code: ipc.CodeServerError, Message: err.Error()}
}

func badRequest(err error) ipc.Response {
	return ipc.Response{Code: ipc.CodeBadRequest, Message: err.Error()}
}

// detailOr 取状态说明当成功文案；说明为空时用兜底文案。
func detailOr(fallback, detail string) string {
	if detail == "" {
		return fallback
	}
	return detail
}

// passwordArg 解出请求里携带的口令。
//
// 参数缺省表示沿用服务进程内存里已有的口令（配置文件里的那份，或上一次
// 请求带来的那份）；带了就是 base64 编码的本次输入。
func passwordArg(args []string, index int) (string, error) {
	arg := ipc.Arg(args, index)
	if arg == "" {
		return "", nil
	}
	password, err := ipc.DecodeSecret(arg)
	if err != nil {
		return "", err
	}
	return password, nil
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
	if st.Failure != "" {
		msg += " | 原因 " + st.Failure
	}
	peer := "未配置"
	if st.WireGuard.Configured {
		peer = "等待握手"
		if st.WireGuard.Ready {
			peer = "已握手"
		}
	}
	msg += " | WireGuard " + peer
	var drops []string
	for reason, count := range st.WireGuard.Drops {
		drops = append(drops, fmt.Sprintf("%s=%d", reason, count))
	}
	if len(drops) > 0 {
		sort.Strings(drops)
		msg += " | 承载丢包 " + strings.Join(drops, ", ")
	}
	if st.Tunnel != nil {
		link := "断开"
		if st.Tunnel.Connected {
			link = "已连接"
		}
		msg += fmt.Sprintf(" | 校园隧道%s，MTU %d", link, st.Tunnel.MTU)
		r := st.Tunnel.Rejected
		msg += fmt.Sprintf(" | 上行拒包：资源 %d，鉴权 %d，分片 %d，MTU %d，容量 %d，格式 %d，链路 %d",
			r.ResourceUnmatched, r.FlowRejected, r.FragmentMissing+r.FragmentOrder,
			r.MTUExceeded, r.PendingFull+r.FlowTableFull+r.FragmentFull, r.InvalidPacket, r.LinkUnavailable)
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
// 只包含 PID、账号、配置路径与端点——都不算秘密，能连上本地端点的人本来
// 就看得到这些文件。
func identityText(id Identity) string {
	text := fmt.Sprintf("pid=%d", id.PID)
	if id.Username != "" {
		text += fmt.Sprintf(" | 账号=%q", id.Username)
	}
	if id.ConfigPath != "" {
		text += fmt.Sprintf(" | 配置=%q", id.ConfigPath)
	}
	if id.Endpoint != "" {
		text += fmt.Sprintf(" | 端点=%q", id.Endpoint)
	}
	return text
}

// RunServer 是服务进程的入口：监听本地端点并处理请求，返回时说明服务已停止。
func RunServer(svc *Service, ln net.Listener) error {
	// 端点由调用方按配置文件的身份解析好（见 ipc.EndpointFor）：这里不再有
	// "默认端点"这个退路，否则配置读不出来时会静默地和另一个实例抢同一个
	// 端点。
	log.Printf("服务进程已开始处理请求")

	srv := NewServer(svc, ln)

	// 两条退出路径：系统信号（Ctrl-C / systemd / 任务计划程序），以及
	// shutdown 命令（njuvpn restart 用的就是它）。
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	stop, joined := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(joined)
		select {
		case sig := <-signals:
			log.Printf("收到信号 %v，准备退出", sig)
		case <-srv.Done():
			log.Printf("收到 shutdown 命令，准备退出")
		case <-svc.Done():
			log.Printf("服务对象已收尾，准备退出")
		case <-stop:
			return
		}
		// 先收尾（含登出）再关监听：CLI 的 restart 用"端点不再响应"判断旧
		// 进程已经退干净。端点若先消失，新进程会和还没发完的登出抢同一个
		// 账号的名额（服务端只允许一条会话）。
		svc.Close()
		srv.Shutdown()
	}()
	// 信号订阅保持到收尾完成才注销，第二个 Ctrl-C 不应中断登出请求。

	err := srv.Serve()
	// Serve 返回说明监听已经关闭；这里再收一次尾（Close 幂等），然后等
	// 在处理的请求写完响应。
	svc.Close()
	srv.Shutdown()
	srv.Wait(shutdownWaitTimeout)
	close(stop)
	<-joined
	return err
}
