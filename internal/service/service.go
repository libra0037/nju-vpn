package service

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libra0037/nju-vpn/internal/config"
	"github.com/libra0037/nju-vpn/internal/dial"
	"github.com/libra0037/nju-vpn/internal/ipc"
	"github.com/libra0037/nju-vpn/internal/socks5"
	"github.com/libra0037/nju-vpn/internal/ztna"
)

// 服务层对外的错误分类。IPC 层据此决定响应状态码，不靠字符串匹配。
var (
	// ErrNotRunning 表示共享会话本来就没有运行。
	ErrNotRunning = errors.New("隧道未运行")
	// ErrBadState 表示当前状态不允许该操作（例如正在登录时又敲 start）。
	// 这是用法问题，不是服务端故障，IPC 层据此回 409。
	ErrBadState = errors.New("当前状态不允许该操作")
	// ErrAuthRequired 表示需要提交验证码才能继续。
	ErrAuthRequired = errors.New("需要二次验证")
	// ErrShuttingDown 表示服务进程正在退出，不再接受新命令。
	ErrShuttingDown = errors.New("服务进程正在退出")
	// ErrStopRequested 表示这条命令在排队期间用户已经请求断开，因此没有执行。
	ErrStopRequested = errors.New("已收到断开请求，这条命令没有执行")
	// ErrEmptyCode 表示请求里没有验证码。属于用法问题，IPC 层回 400。
	ErrEmptyCode = errors.New("验证码为空")
	// ErrMissingCredential 表示这次操作没有可用的凭据（配置里没写 username，
	// 或者口令既没写在配置里、也没在这次请求里带上）。属于用法问题：按状态码
	// 分流的脚本不该把一个输入问题当成服务进程故障。
	ErrMissingCredential = errors.New("缺少可用凭据")
)

// closeGrace 是 Close 等待 actor 收尾的上限。正常收尾就是一次登出请求，
// 登出自身有超时，这里给足余量但不无限等。
const closeGrace = 30 * time.Second

// authWaitTimeout 是等待验证码的上限。
//
// 用户在提示符前直接关掉终端时，进程会一直停在 auth_pending，服务端那条
// "同一账号只允许一条隧道会话"的名额也跟着被占住。到点就登出，宁可让用户
// 重新 start 一次。
const defaultAuthWaitTimeout = 10 * time.Minute
const defaultCommandTimeout = 2 * time.Minute

type Options struct {
	Dial             dial.DialFunc
	ControlRootCAs   *x509.CertPool // 离线测试的受控信任；生产使用系统信任链。
	AuthWaitTimeout  time.Duration
	CommandTimeout   time.Duration // 包括排队及执行；0 使用两分钟预算。
	ReconnectBackoff time.Duration
}

type commandKind int

const (
	cmdStart commandKind = iota
	cmdDevices
	cmdAuth
	cmdAuthTimeout
	cmdStop
	cmdTunnelDown
	cmdTunnelRetry
	cmdTunnelRestored
	cmdSessionEnded
	cmdSOCKSDown
	cmdEndpointStart
	cmdEndpointStop
)

func (k commandKind) String() string {
	switch k {
	case cmdStart:
		return "start"
	case cmdDevices:
		return "devices"
	case cmdAuth:
		return "auth"
	case cmdAuthTimeout:
		return "auth-timeout"
	case cmdStop:
		return "stop"
	case cmdTunnelDown:
		return "tunnel-down"
	case cmdTunnelRetry:
		return "tunnel-retry"
	case cmdTunnelRestored:
		return "tunnel-restored"
	case cmdSessionEnded:
		return "session-ended"
	case cmdSOCKSDown:
		return "socks-down"
	case cmdEndpointStart:
		return "endpoint-start"
	case cmdEndpointStop:
		return "endpoint-stop"
	}
	return "unknown"
}

type command struct {
	kind     commandKind
	sess     *ztna.Session
	socks    *socks5.Server
	endpoint string
	ctx      context.Context // 用户命令拥有总等待预算；内部事件没有此字段。
	// arg 是本次请求带上来的口令（start / trust / untrust）或验证码（auth）。
	arg string
	// trust 与 all 是授信终端操作的参数：trust 表示"绑成授信终端"，
	// all 表示"解除该账号下全部授信终端"。
	trust bool
	all   bool
	// gen 是隧道代次，seq 是等待验证码的轮次：两者都用来丢弃过期汇报。
	gen uint64
	seq uint64
	// attempt 是重连次数，err 是断开原因或内部错误。
	attempt int
	err     error
	reply   chan error
}

// credentials 是一次登录要用到的东西。
//
// 配置文件里的口令只是初始值：start 可以带上本次输入的口令，服务进程把它
// 留在内存里，供后续操作（重新登录、重连后重登、授信终端操作）复用。
// 全程不落盘、不进 argv、不进日志。
type credentials struct {
	username string
	password string
}

// pendingOp 是一次停在"等验证码"那一步的操作。
//
// 它必须持有半完成的会话对象：丢掉它就没法登出，服务端那条"同一账号只
// 允许一条隧道会话"的名额会一直占着，直到它自己超时。
type pendingOp struct {
	kind  commandKind // cmdStart 或 cmdDevices
	trust bool        // cmdStart：登录成功后顺带绑授信终端
	all   bool        // cmdDevices：解除全部
	sess  *ztna.Session
	dev   *ztna.DeviceSession
}

// auth 提交验证码，继续这次登录。
func (p *pendingOp) auth(ctx context.Context, code string) error {
	if p.dev != nil {
		return p.dev.Auth(ctx, code)
	}
	return p.sess.Auth(ctx, code)
}

// prompt 让服务端把验证码发出去，并返回给用户看的提示。
//
// 只报告"手机号是多少"是不够的：短信要走到这里的发送接口才真的发出来。
// 发送失败（例如冷却期内被拒）时退回手机号提示，用户至少知道验证码会发到哪。
func (p *pendingOp) prompt(ctx context.Context) string {
	var hint string
	var text string
	var err error
	if p.dev != nil {
		hint = p.dev.Hint(ctx)
		text, err = p.dev.SMSPrompt(ctx)
	} else {
		hint = p.sess.SMSHint(ctx)
		text, err = p.sess.SMSPrompt(ctx)
	}
	if err != nil {
		log.Printf("发送验证码失败: %v", err)
	}
	switch {
	case text != "" && hint != "":
		return text + "（" + hint + "）"
	case text != "":
		return text
	default:
		return hint
	}
}

// close 释放这次半完成的登录：能登出就登出，释放服务端的名额。
func (p *pendingOp) close(ctx context.Context) error {
	if p.dev != nil {
		return p.dev.Close(ctx)
	}
	if p.sess != nil {
		return p.sess.Close(ctx)
	}
	return nil
}

// Service 拥有共享校园会话及各端点的启停任务。
//
// 所有会改状态的操作都在 loop 这一个协程里执行：调用方把命令放进 cmds 并
// 等一个回复。这样就不需要在持锁状态下做网络 I/O——登录、短信、建隧道都
// 可能是分钟级，持锁做它们等于让退出路径永远拿不到锁。
type Service struct {
	cfg           *config.Config
	status        *statusStore
	br            *bearer
	brSnapshot    atomic.Pointer[bearer]
	socks         *socks5.Server
	socksSnapshot atomic.Pointer[socks5.Server]
	socksCancel   context.CancelFunc
	socksDone     chan struct{}
	rootCancel    context.CancelFunc
	rootDone      chan struct{}

	// cred 只在 actor 协程里读写，不需要加锁。
	cred credentials

	cmds      chan *command
	closed    chan struct{}
	actorDone chan struct{}
	closeOnce sync.Once

	mu       sync.Mutex
	opCancel context.CancelFunc
	// stopPending 记录"用户已经请求断开"。它不只打断正在执行的那条命令，
	// 还要让排队中的登录类命令别在 stop 之后接着跑完——命令在 actor 里
	// 串行，一次登录最坏几分钟，等它跑完再断，用户看到的是"stop 卡住、
	// 隧道随后又被建起来"。
	stopPending atomic.Bool

	// 以下字段只在 actor 协程里访问，不需要加锁。
	//
	// dialer 是测试注入点：注入的是拨号实现，Server / DialAddr 这些生产接线
	// 仍然由 clientFor 算出来，测试因此必须走真实的那条路径。
	dialer           dial.DialFunc
	controlRootCAs   *x509.CertPool
	client           *ztna.Client
	session          *ztna.Session
	pending          *pendingOp
	runCancel        context.CancelFunc
	runDone          chan struct{}
	authWaitTimeout  time.Duration
	commandTimeout   time.Duration
	reconnectBackoff time.Duration
	sessionSnapshot  atomic.Pointer[ztna.Session]
	events           chan *command
	gen              uint64
	// authTimer 只在 auth_pending 期间有效，到点由 actor 收尾。
	authTimer *time.Timer
	// authSeq 是"等待验证码"的轮次，每次起停自增。计时器触发时把当时的
	// 轮次带进命令里，迟到的命令因此能被认出来并丢掉。
	authSeq uint64
}

// New 构造服务对象并启动命令循环。
//
// 承载设备在这里就建起来，理由见 bearer 的注释。
func New(cfg *config.Config, options ...Options) (*Service, error) {
	if cfg == nil {
		return nil, errors.New("缺少服务配置")
	}
	if _, err := cfg.NodeSPKIPins(); err != nil {
		return nil, err
	}
	if len(options) > 1 {
		return nil, errors.New("只能提供一组服务参数")
	}
	copyCfg := *cfg
	copyCfg.PinnedNodeSPKISHA256 = slices.Clone(cfg.PinnedNodeSPKISHA256)
	cfg = &copyCfg
	opts := Options{}
	if len(options) > 0 {
		opts = options[0]
	}
	if opts.ControlRootCAs != nil {
		opts.ControlRootCAs = opts.ControlRootCAs.Clone()
	}
	if opts.AuthWaitTimeout == 0 {
		opts.AuthWaitTimeout = defaultAuthWaitTimeout
	}
	if opts.AuthWaitTimeout < 0 {
		return nil, errors.New("验证码等待时间须为正数")
	}
	if opts.CommandTimeout == 0 {
		opts.CommandTimeout = defaultCommandTimeout
	}
	if opts.CommandTimeout < 0 || opts.ReconnectBackoff < 0 {
		return nil, errors.New("命令预算与重连退避须为正数")
	}
	var br *bearer
	var socks *socks5.Server
	var wgErr, socksErr error
	if cfg.WireGuard.Enabled {
		br, wgErr = newBearer(cfg)
	}
	if cfg.SOCKS5.Enabled {
		socks, socksErr = newSOCKS(cfg)
	}
	if (cfg.WireGuard.Enabled || cfg.SOCKS5.Enabled) && br == nil && socks == nil {
		return nil, errors.Join(wgErr, socksErr)
	}

	s := &Service{
		cfg:              cfg,
		status:           newStatusStore(identityOf(cfg)),
		br:               br,
		socks:            socks,
		cred:             credentials{username: cfg.Username, password: cfg.Password},
		cmds:             make(chan *command, 32),
		events:           make(chan *command, 16),
		closed:           make(chan struct{}),
		actorDone:        make(chan struct{}),
		dialer:           opts.Dial,
		controlRootCAs:   opts.ControlRootCAs,
		authWaitTimeout:  opts.AuthWaitTimeout,
		commandTimeout:   opts.CommandTimeout,
		reconnectBackoff: opts.ReconnectBackoff,
	}
	s.brSnapshot.Store(br)
	s.socksSnapshot.Store(socks)
	s.status.endpoint(true, cfg.WireGuard.Enabled, wgErr)
	s.status.endpoint(false, cfg.SOCKS5.Enabled, socksErr)
	go s.loop()
	return s, nil
}

// identityOf 组装实例身份，只在启动时算一次。
//
// 端点规则与 CLI 共用 ipc.EndpointFor：两处算错任何一处，
// 命令就会打到别的实例上，那边的账号会被静默操作。
func identityOf(cfg *config.Config) Identity {
	return Identity{
		PID:        os.Getpid(),
		ConfigPath: cfg.SourcePath(),
		Endpoint:   ipc.EndpointFor(cfg.SourcePath()),
		Username:   cfg.Username,
	}
}

// Status 返回当前状态快照。它不经过 actor，永远立即可用。
//
// 端点诊断从当前对象派生；L3 地址只在真实连接可用时返回。
func (s *Service) Status() Status {
	st := s.status.Get()
	if br := s.brSnapshot.Load(); br != nil {
		st.WireGuard.Diagnostics = br.dev.Diagnostics()
		st.WireGuard.Listening = true
	}
	if socks := s.socksSnapshot.Load(); socks != nil {
		st.SOCKS5.Diagnostics = socks.Diagnostics()
	}
	closing := false
	select {
	case <-s.closed:
		closing = true
	default:
	}
	if sess := s.sessionSnapshot.Load(); sess != nil && sess.Err() == nil && st.State == StateUp && !closing {
		st.SessionReady = true
		if st.WireGuard.Enabled {
			d := sess.Diagnostics()
			st.Tunnel = &d
			if d.Connected {
				st.PeerIP = s.cfg.WireGuard.PeerAddress
				if ip := sess.ClientIP(); ip != nil {
					st.ClientIP = ip.String()
				}
			}
		}
	}
	st.Ready = st.SessionReady && (st.WireGuard.Enabled || st.SOCKS5.Enabled) &&
		(!st.WireGuard.Enabled || st.WireGuard.Listening && st.Tunnel != nil && st.Tunnel.Connected && !st.Retrying) &&
		(!st.SOCKS5.Enabled || st.SOCKS5.Listening && st.SOCKS5.Failure == "")

	return st
}

// Identity 返回实例身份。
func (s *Service) Identity() Identity { return s.status.Get().Identity }

// Done 在服务对象开始收尾（Close 被调用）时关闭。
//
// 服务进程的主循环靠它解阻塞：Close 可能来自任何一处（信号、shutdown
// 命令、调用方的 defer），监听套接字必须跟着一起收掉。
func (s *Service) Done() <-chan struct{} { return s.closed }

// BearerSummary 描述承载层的监听状态，供启动日志用。
func (s *Service) BearerSummary() string {
	msg := ""
	if br := s.brSnapshot.Load(); br != nil {
		msg = "WireGuard " + br.summary()
	}
	if socks := s.socksSnapshot.Load(); socks != nil {
		if msg != "" {
			msg += "；"
		}
		msg += fmt.Sprintf("SOCKS5 TCP %d 已监听", socks.Diagnostics().Port)
	}
	if msg == "" {
		return "数据端点未启用"
	}
	return msg
}

// Start 建立隧道：登录、取资源表、建隧道，必要时把本机绑成授信终端。
//
// password 非空时替换内存里的口令：配置里不写口令的部署靠它把口令带进来。
// 服务端要求二次验证时切到 auth_pending 并返回 ErrAuthRequired，调用方拿
// 到验证码后调用 Auth 继续。
func (s *Service) Start(trust bool, password string) error {
	return s.call(&command{kind: cmdStart, arg: password, trust: trust})
}

// Trust 把本机绑成授信终端。隧道在跑时复用当前会话，否则单独登录一次。
func (s *Service) Trust(password string) error {
	return s.call(&command{kind: cmdDevices, arg: password, trust: true})
}

// Untrust 解除授信：all 为真时解除该账号下全部授信终端。
func (s *Service) Untrust(password string, all bool) error {
	return s.call(&command{kind: cmdDevices, arg: password, trust: false, all: all})
}

// Auth 提交二次验证码。仅在 auth_pending 状态下有效。
func (s *Service) Auth(code string) error {
	return s.call(&command{kind: cmdAuth, arg: code})
}

// Stop 断开隧道并释放资源。
//
// 先打断正在进行的操作再排队：命令在 actor 里串行，而一次登录最坏要走
// 几分钟，stop 的语义却是"现在就断"。被打断的那条以取消收场，随后这条
// stop 照常执行——用户不必转去手工杀进程，而手工杀会跳过登出。
func (s *Service) Stop() error {
	s.stopPending.Store(true)
	s.cancelOp()
	return s.call(&command{kind: cmdStop})
}

// Close 停止命令循环、释放资源并通知服务端登出。可安全重复调用。
//
// 与 Stop 的区别是不判断状态、不返回错误：进程退出路径必须执行它。服务端
// 同一账号只允许一条隧道会话，残留会话会让后续建隧道被拒。
func (s *Service) Close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		// 打断正在进行的网络 I/O，让 actor 尽快回到循环里收尾。
		s.cancelOp()

		select {
		case <-s.actorDone:
		case <-time.After(closeGrace):
			log.Printf("服务进程收尾超过 %s，放弃等待", closeGrace)
		}

		// 可变端点由 actor 释放；预算耗尽也不跨协程读取它的私有字段。
	})
}

// call 把命令交给 actor 并等回复。
func (s *Service) call(cmd *command) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.commandTimeout)
	defer cancel()
	cmd.ctx = ctx
	cmd.reply = make(chan error, 1)

	if cmd.kind == cmdStop {
		// Stop 已取消正在执行的操作，须在有界预算内等到入队；不能因队列
		// 已满而只留下 stopPending，却没有真正执行摘除与登出。
		select {
		case s.cmds <- cmd:
		case <-s.closed:
			return ErrShuttingDown
		case <-ctx.Done():
			return ctx.Err()
		}
	} else {
		select {
		case s.cmds <- cmd:
		case <-s.closed:
			return ErrShuttingDown
		default:
			return fmt.Errorf("%w：命令队列已满", ErrBadState)
		}
	}

	select {
	case err := <-cmd.reply:
		return err
	case <-s.closed:
		return ErrShuttingDown
	case <-ctx.Done():
		return ctx.Err()
	}
}

// setOpCancel 记录当前操作的取消函数。
func (s *Service) setOpCancel(cancel context.CancelFunc) {
	s.mu.Lock()
	s.opCancel = cancel
	s.mu.Unlock()
}

// cancelOp 取消正在进行的操作。
func (s *Service) cancelOp() {
	s.mu.Lock()
	cancel := s.opCancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// loop 是 actor 主循环。
func (s *Service) loop() {
	defer close(s.actorDone)
	for {
		select {
		case <-s.closed:
			s.teardown("服务进程退出")
			s.brSnapshot.Store(nil)
			if s.br != nil {
				s.br.close()
				s.br = nil
			}
			return
		case cmd := <-s.cmds:
			s.dispatch(cmd)
		case event := <-s.events:
			s.dispatch(event)
		}
	}
}

// dispatch 执行一条命令。
//
// 这里是最外层 panic 边界：任何一处未预料到的崩溃都会转成一次失败，而不是
// 带走整个进程——服务端的会话还开着，进程直接死掉就没人登出了。
func (s *Service) dispatch(cmd *command) {
	parent := cmd.ctx
	if parent == nil {
		parent = context.Background()
	} else if err := parent.Err(); err != nil {
		cmd.reply <- err
		return
	}
	ctx, cancel := context.WithCancel(parent)
	s.setOpCancel(cancel)

	replied := false
	reply := func(err error) {
		if replied {
			return
		}
		replied = true
		select {
		case cmd.reply <- err:
		default:
		}
	}

	defer func() {
		s.setOpCancel(nil)
		cancel()

		if recover() != nil {
			err := errors.New("命令处理发生内部错误")
			log.Printf("%v", err)
			s.teardown("")
			s.status.setError(err.Error(), err)
			reply(err)
		}
	}()

	// 退出期间不再执行新命令：Close 已经走过登出，此时再建隧道会留下
	// 没人管的会话。隧道协程的汇报例外——丢掉它会让状态卡在 up。
	if cmd.kind != cmdTunnelDown && cmd.kind != cmdTunnelRetry && cmd.kind != cmdTunnelRestored && cmd.kind != cmdSessionEnded && cmd.kind != cmdSOCKSDown {
		select {
		case <-s.closed:
			reply(ErrShuttingDown)
			return
		default:
		}
	}

	// 用户已经请求断开时，排队中的登录类命令不再执行：它们会在那条 stop
	// 之后接着登录、发短信、建隧道，用户看到的是"stop 卡住，可隧道后来又
	// 自己起来了"。stop 自己当然要放行，它正是来清这个标记的。
	if s.stopPending.Load() {
		switch cmd.kind {
		case cmdStart, cmdDevices, cmdAuth, cmdEndpointStart:
			log.Printf("已收到断开请求，丢弃排队中的 %s 命令", cmd.kind)
			reply(ErrStopRequested)
			return
		}
	}

	var err error
	switch cmd.kind {
	case cmdStart:
		err = s.start(ctx, cmd.trust, cmd.arg)
	case cmdDevices:
		err = s.devices(ctx, cmd.trust, cmd.all, cmd.arg)
	case cmdAuth:
		err = s.auth(ctx, cmd.arg)
	case cmdAuthTimeout:
		err = s.authTimeout(cmd.seq)
	case cmdStop:
		err = s.stop()
	case cmdTunnelDown:
		err = s.tunnelDown(cmd.gen, cmd.err)
	case cmdTunnelRetry:
		err = s.tunnelRetry(cmd.gen, cmd.attempt, cmd.err)
	case cmdTunnelRestored:
		err = s.tunnelRestored(cmd.gen)
	case cmdSessionEnded:
		if s.session == cmd.sess {
			err = s.fail(cmd.err)
		}
	case cmdSOCKSDown:
		if s.session == cmd.sess && s.socks == cmd.socks {
			s.stopSOCKS()
			s.status.endpoint(false, true, cmd.err)
			if !s.status.Get().WireGuard.Enabled {
				err = s.fail(cmd.err)
			}
		}
	case cmdEndpointStart:
		err = s.startEndpoint(ctx, cmd.endpoint)
	case cmdEndpointStop:
		err = s.stopEndpoint(cmd.endpoint)
	default:
		err = fmt.Errorf("未知命令 %d", cmd.kind)
	}
	reply(err)
}

// start 建立隧道。
func (s *Service) start(ctx context.Context, trust bool, password string) error {
	if !s.cfg.WireGuard.Enabled && !s.cfg.SOCKS5.Enabled {
		return fmt.Errorf("%w：没有启用数据端点", ErrBadState)
	}
	switch s.status.Get().State {
	case StateAuthPending:
		// 等待验证码时再次 start，意味着用户没收到码、想重新要一条：
		// 丢掉上一次半完成的登录，从头来一遍。
		s.teardown("重新登录")
	case StateIdle, StateError:
		s.teardown("")
	default:
		return fmt.Errorf("%w: 当前状态是 %s", ErrBadState, s.status.Get().State)
	}

	pw, err := s.applyPassword(password)
	if err != nil {
		return s.fail(err)
	}
	client, err := s.clientFor()
	if err != nil {
		return s.fail(err)
	}
	s.client = client
	s.status.set(StateLoggingIn, "正在登录")

	sess, err := client.Connect(ctx, ztna.ConnectOptions{Password: pw})
	if err != nil {
		if authErr, ok := ztna.AsAuthRequired(err); ok {
			s.pending = &pendingOp{kind: cmdStart, trust: trust, sess: sess}
			return s.awaitAuth(ctx, authErr.Hint)
		}
		// 失败也可能已经占住了服务端的会话：留着它，teardown 才登得出去。
		s.attach(sess)
		return s.fail(err)
	}
	if trust {
		if err := s.ensureTrusted(ctx, sess); err != nil {
			s.attach(sess)
			return s.fail(err)
		}
	}
	return s.finishConnect(ctx, sess)
}

// devices 是 trust / untrust 的实现。
//
// 隧道在跑时复用正在跑的会话：服务端同一账号只允许一条会话，另开一条会把
// 正在跑的隧道挤掉，短信模式下还要再花一条验证码。隧道没在跑时为这次操作
// 单独登录一次，操作完就登出——那次登录只是为了拿到操作资格。
func (s *Service) devices(ctx context.Context, trust, all bool, password string) error {
	switch s.status.Get().State {
	case StateUp:
		return s.runDeviceOp(ctx, s.session.Devices(), trust, all)
	case StateAuthPending:
		s.teardown("重新登录")
	}

	pw, err := s.applyPassword(password)
	if err != nil {
		return s.fail(err)
	}
	client, err := s.clientFor()
	if err != nil {
		return s.fail(err)
	}
	s.client = client
	s.status.set(StateLoggingIn, "正在登录")

	d, err := client.OpenDevices(ctx, pw)
	if err != nil {
		if authErr, ok := ztna.AsAuthRequired(err); ok {
			s.pending = &pendingOp{kind: cmdDevices, trust: trust, all: all, dev: d}
			return s.awaitAuth(ctx, authErr.Hint)
		}
		// 登录失败也可能已经占住了服务端会话，同样要登出。
		if d != nil {
			if cerr := d.Close(context.Background()); cerr != nil {
				log.Printf("释放登录会话: %v", cerr)
			}
		}
		return s.fail(err)
	}
	return s.runDeviceOp(ctx, d, trust, all)
}

// runDeviceOp 执行一次授信终端操作并把结果写进状态说明。
//
// 自带登录的那种（隧道没在跑）操作完就登出：留着它只会占住服务端那条唯一
// 的名额，而这次操作并不需要保持在线。
func (s *Service) runDeviceOp(ctx context.Context, d *ztna.DeviceSession, trust, all bool) error {
	own := d.OwnsSession()
	if own {
		defer func() {
			if err := d.Close(context.Background()); err != nil {
				log.Printf("释放授信终端操作占用的登录: %v", err)
			}
		}()
	}

	var (
		st  ztna.DeviceStatus
		err error
	)
	switch {
	case trust:
		st, err = d.Trust(ctx)
	case all:
		st, err = d.Untrust(ctx, true)
	default:
		st, err = d.Untrust(ctx, false)
	}
	if err != nil {
		return s.fail(err)
	}
	detail := deviceSummary(trust, all, st)
	if !own {
		// 隧道在跑：这次操作只是顺手做的事，状态与地址都不动。
		s.status.setDetail(detail)
		return nil
	}
	// 自带登录的那种：登录不是为了隧道，操作完就该回到 idle——
	// 留在 logging_in 会让人以为还有事在半路上。
	s.status.set(StateIdle, detail)
	return nil
}

// deviceSummary 把操作结果写成人看的一行。
func deviceSummary(trust, all bool, st ztna.DeviceStatus) string {
	var head string
	switch {
	case trust:
		head = "已确认为授信终端"
	case all:
		head = "已解除全部授信终端"
	default:
		head = "已解除本机授信"
	}
	state := "本机未授信"
	if st.Trusted {
		state = "本机已授信"
	}
	return fmt.Sprintf("%s（%d/%d，%s）", head, st.Count, st.Max, state)
}

// auth 提交二次验证码，继续停在 auth_pending 的那次操作。
func (s *Service) auth(ctx context.Context, code string) error {
	p := s.pending
	if p == nil || s.status.Get().State != StateAuthPending {
		return fmt.Errorf("%w: 当前状态是 %s，不需要验证码", ErrBadState, s.status.Get().State)
	}
	if code == "" {
		return ErrEmptyCode
	}

	if err := p.auth(ctx, code); err != nil {
		if authErr, ok := ztna.AsAuthRequired(err); ok {
			// 服务端又要一次验证码（上一条过期了之类）：留在等待状态，
			// 提示也换成新的一条。
			return s.awaitAuth(ctx, authErr.Hint)
		}
		if _, ok := ztna.AsRejected(err); ok {
			// 验证码本身不对：会话还活着，用户可以再输一次。
			s.status.setDetail(err.Error())
			return err
		}
		return s.fail(err)
	}

	s.stopAuthTimer()
	s.pending = nil
	if p.dev != nil {
		return s.runDeviceOp(ctx, p.dev, p.trust, p.all)
	}
	if p.trust {
		if err := s.ensureTrusted(ctx, p.sess); err != nil {
			s.attach(p.sess)
			return s.fail(err)
		}
	}
	return s.finishConnect(ctx, p.sess)
}

// ensureTrusted 把本机绑成授信终端；只有共享 SID 失效终止数据端点启动。
//
// 绑定失败不该影响隧道：拿到的网络能力是一样的，只是下次登录还要再做一次
// 二次验证。
func (s *Service) ensureTrusted(ctx context.Context, sess *ztna.Session) error {
	if err := sess.EnsureTrusted(ctx); err != nil {
		var gone *ztna.ErrSessionGone
		if errors.As(err, &gone) {
			return gone
		}
		log.Printf("绑定授信终端失败（不影响隧道）: %v", err)
	}
	return nil
}

// awaitAuth 切到等待验证码状态。
func (s *Service) awaitAuth(ctx context.Context, hint string) error {
	if p := s.pending; p != nil {
		if text := p.prompt(ctx); text != "" {
			hint = text
		}
	}
	if hint == "" {
		hint = "服务端要求短信验证码"
	}
	s.status.set(StateAuthPending, hint)
	s.startAuthTimer()
	return fmt.Errorf("%s: %w", hint, ErrAuthRequired)
}

// startAuthTimer 在等待验证码时启动上限。
//
// 每次进入 auth_pending 都重新计时：验证码输错后还能再输，不该被上一个
// 计时器打断。
func (s *Service) startAuthTimer() {
	s.stopAuthTimer()
	seq := s.authSeq
	s.authTimer = time.AfterFunc(s.authWaitTimeout, func() { s.reportAuthTimeout(seq) })
}

// stopAuthTimer 取消等待验证码的上限。
//
// 同时推进轮次：计时器可能已经触发、命令正排在队列里，推进之后那条迟到
// 的命令就能认出自己是过期的。
func (s *Service) stopAuthTimer() {
	s.authSeq++
	if s.authTimer != nil {
		s.authTimer.Stop()
		s.authTimer = nil
	}
}

// reportAuthTimeout 把"等验证码超时"交给 actor。
//
// 与隧道协程的收尾一样必须经过 actor：直接改状态会与正在执行的命令打架。
func (s *Service) reportAuthTimeout(seq uint64) {
	select {
	case s.cmds <- &command{kind: cmdAuthTimeout, seq: seq, reply: make(chan error, 1)}:
	case <-s.closed:
	}
}

// authTimeout 处理"等验证码等到超时"。
//
// 只做收尾：用户可能只是走开了，回来后重新 start（会重新登录）即可。
func (s *Service) authTimeout(seq uint64) error {
	if seq != s.authSeq {
		// 上一轮的计时器：那一轮早已收场（验证码输对了、或者用户重新
		// start 了），这条命令什么都不能动。
		return nil
	}
	if s.status.Get().State != StateAuthPending {
		return nil
	}
	s.teardown("")
	detail := fmt.Sprintf("等待验证码超过 %s，已登出；重新建立隧道请执行 njuvpn start",
		s.authWaitTimeout.Round(time.Minute))
	log.Print(detail)
	s.status.setError(detail, context.DeadlineExceeded)
	return nil
}

// stop 断开隧道。
func (s *Service) stop() error {
	// 标记到这里就完成了使命：这条 stop 之后到达的命令都是新意图。
	s.stopPending.Store(false)
	// idle 只由 runDeviceOp（自带登录的那次设备操作）与 teardown 落地，两者
	// 走到那里时 session 与 pending 都已经清空，所以只看状态就够。
	if s.status.Get().State == StateIdle {
		return ErrNotRunning
	}
	s.teardown("隧道已断开")
	return nil
}

// finishConnect 用一次成功的连接建立承载。
func (s *Service) finishConnect(ctx context.Context, sess *ztna.Session) error {
	s.attach(sess)
	s.status.set(StateUp, "校园会话已登录")
	s.status.endpoint(true, s.cfg.WireGuard.Enabled, nil)
	s.status.endpoint(false, s.cfg.SOCKS5.Enabled, nil)
	var wgErr, socksErr error
	// 接入先准备 L4，L3 的建连或错误不会持有其拨号/转发任务。
	if s.cfg.SOCKS5.Enabled {
		socksErr = s.startSOCKS(ctx)
	}
	if s.cfg.WireGuard.Enabled {
		wgErr = s.startL3(ctx)
	}
	if ctx.Err() != nil {
		return s.fail(ctx.Err())
	}
	if s.session == nil {
		return s.fail(ErrNotRunning)
	}
	if sess.Err() != nil {
		return s.fail(sess.Err())
	}
	if (wgErr != nil || !s.cfg.WireGuard.Enabled) && (socksErr != nil || !s.cfg.SOCKS5.Enabled) {
		return s.fail(errors.Join(wgErr, socksErr))
	}
	s.status.setRetrying(false)
	if wgErr != nil || socksErr != nil {
		s.status.setDetail("校园会话已登录，部分端点启动失败")
	} else {
		s.status.setDetail("数据端点已启动")
	}
	rootCtx, cancel := context.WithCancel(context.Background())
	s.rootCancel = cancel
	s.rootDone = make(chan struct{})
	done := s.rootDone
	go func() {
		defer close(done)
		select {
		case <-sess.Done():
			s.report(rootCtx, &command{kind: cmdSessionEnded, sess: sess, err: sess.Err()})
		case <-rootCtx.Done():
		}
	}()
	return nil
}

// attach 接管一次连接的会话对象。失败路径同样要接管：Connect 在部分失败
// 时会返回一个已经占住服务端名额的会话，只有拿着它才能登出。
func (s *Service) attach(sess *ztna.Session) {
	if sess == nil {
		return
	}
	prev := s.session
	s.session = sess
	s.sessionSnapshot.Store(sess)
	if prev == nil || prev == sess {
		return
	}
	if err := prev.Close(context.Background()); err != nil {
		log.Printf("释放上一个会话: %v", err)
	}
}

// runTunnel 跑隧道协程：维持链路，退出时向 actor 汇报。
func (s *Service) runTunnel(ctx context.Context, sess *ztna.Session, gen uint64) {
	defer func() {
		// 隧道协程没有命令层的 recover 保护：真崩了要收敛成一次"隧道
		// 断开"，而不是带走整个进程（进程一死就没人登出了）。
		if recover() != nil {
			panicErr := errors.New("隧道运行任务发生内部错误")
			log.Printf("%v", panicErr)
			s.report(ctx, &command{kind: cmdTunnelDown, gen: gen, err: panicErr})
		}
	}()
	events := ztna.LinkEvents{
		Dropped: func(attempt int, err error) {
			s.report(ctx, &command{kind: cmdTunnelRetry, gen: gen, attempt: attempt, err: err})
		},
		Restored: func() { s.report(ctx, &command{kind: cmdTunnelRestored, gen: gen}) },
	}
	err := sess.Run(ctx, events)
	s.report(ctx, &command{kind: cmdTunnelDown, gen: gen, err: err})
}

// report 投递一条来自隧道协程的汇报。投不进去（进程正在退出）就丢掉。
func (s *Service) report(ctx context.Context, cmd *command) {
	cmd.reply = make(chan error, 1)
	select {
	case s.events <- cmd:
	case <-s.closed:
	case <-ctx.Done():
	}
}

// tunnelDown 处理隧道运行期断开。
//
// 代次检查是必须的：Stop 之后旧协程可能还在退避重连，它退出时新会话早就
// 建立了，不做区分就会把新会话一起拆掉。
func (s *Service) tunnelDown(gen uint64, err error) error {
	if gen != s.gen {
		log.Printf("忽略过期隧道协程的退出（第 %d 代，当前第 %d 代）: %v", gen, s.gen, err)
		return nil
	}
	log.Printf("隧道断开: %v", err)
	var gone *ztna.ErrSessionGone
	if !errors.As(err, &gone) && s.status.Get().SOCKS5.Enabled {
		s.stopL3()
		s.status.endpoint(true, true, err)
		s.status.setRetrying(false)
		s.status.setDetail("L3 已停止，SOCKS5 继续提供服务")
		return nil
	}
	s.teardown("")
	detail := "隧道已断开"
	if err != nil {
		detail += ": " + err.Error()
	}
	s.status.setError(detail, err)
	// 重连窗口已经用尽：进程还活着，但不会自己去重新登录（重新登录可能要
	// 人输验证码）。把恢复命令写进日志，别让用户对着 error 猜。
	log.Printf("隧道已停止，等待人工恢复：njuvpn start（会重新登录一次）")
	return nil
}

// tunnelRetry 在状态里标出"正在重连"。
//
// 只改说明文字：状态仍是 up，因为登录会话、隧道对象与承载层都还在，
// 重连成功后不需要重建它们。
//
// 守卫只认 StateUp：状态不是 up 时隧道协程的这一代早就结束了（teardown
// 推进代次，代次检查会先把这条汇报丢掉），放宽到 error 只会让人以为
// "error 状态下也该标正在重连"。
func (s *Service) tunnelRetry(gen uint64, attempt int, err error) error {
	if gen != s.gen {
		return nil
	}
	if s.status.Get().State != StateUp {
		return nil
	}
	s.status.setLinkFailure(fmt.Sprintf("隧道断开，正在重连（第 %d 次）: %v", attempt, err), err)
	return nil
}

// tunnelRestored 清掉"正在重连"的标记。
func (s *Service) tunnelRestored(gen uint64) error {
	if gen != s.gen {
		return nil
	}
	if s.status.Get().State != StateUp {
		return nil
	}
	s.status.setRetrying(false)
	s.status.setDetail(fmt.Sprintf("链路已恢复（%s）", time.Now().Format("15:04:05")))
	return nil
}

// fail 收敛到 error 状态。只能在 actor 协程内调用。
func (s *Service) fail(err error) error {
	s.teardown("")
	s.status.setError(err.Error(), err)
	return err
}

// teardown 释放本次连接的全部资源并回到 idle。只能在 actor 协程内调用。
//
// 承载设备不在释放之列：它活到进程结束，这里只把这次会话从它上面摘掉。
// 登出失败会写进状态说明：会话对象没了，但服务端那边可能还占着名额，
// 用户需要知道"下次 start 可能被拒"而不是看到一个干净的 idle。
func (s *Service) teardown(detail string) {
	// 代次立刻推进：这一代已经不存在了。它之后投进来的汇报（断开、正在重连、
	// 链路恢复）都不该再被受理——否则用户会在 error 状态下看到一句"正在重连
	// （第 N 次）"，而根本没有东西在重连，巡检脚本也会被这句误导。
	s.gen++
	// 先停表再登出：登出可能要几十秒，而计时器到点会按"等验证码超时"
	// 收尾——那会把紧接着的一轮操作（用户重新 start）一起拆掉。
	s.stopAuthTimer()
	if s.runCancel != nil {
		s.runCancel()
		s.runCancel = nil
	}
	s.sessionSnapshot.Store(nil)
	// 先撤销就绪，再等待任何关闭/登出 I/O。
	if s.status.Get().State != StateIdle {
		s.status.set(StateIdle, detail)
	}
	if s.rootCancel != nil {
		s.rootCancel()
		s.rootCancel = nil
	}
	if s.rootDone != nil {
		<-s.rootDone
		s.rootDone = nil
	}
	// 先停止接入及转发，再释放共享会话；本地 L3 也必须先打断阻塞写入。
	s.stopSOCKS()
	s.stopL3()
	var logoutErr error
	if s.pending != nil {
		logoutErr = s.pending.close(context.Background())
		s.pending = nil
	}
	if s.session != nil {
		logoutErr = s.session.Close(context.Background())
		s.session = nil
	}
	if logoutErr != nil {
		log.Printf("释放会话时出错: %v", logoutErr)
		s.status.setDetail(fmt.Sprintf("%s（登出未成功: %v，服务端名额可能仍被占用）", detail, logoutErr))
	}

}

// applyPassword 决定这次操作用哪个口令，并留在内存里供后续复用。
func (s *Service) applyPassword(password string) (string, error) {
	if password != "" {
		s.cred.password = password
	}
	if s.cred.username == "" {
		return "", fmt.Errorf("%w：配置文件里缺少 username", ErrMissingCredential)
	}
	if s.cred.password == "" {
		return "", fmt.Errorf("%w：没有可用的口令——配置文件里的 password 为空，且这次请求"+
			"没有带上；请在 njuvpn start 的提示下输入", ErrMissingCredential)
	}
	return s.cred.password, nil
}

// clientFor 按当前配置构造协议层客户端。
//
// 每次操作都新建一个：控制面会话（cookie、CSRF 令牌）只属于一次登录，
// 跨操作复用会让"上一次会话已经失效"这种问题表现成别处的怪错误。
func (s *Service) clientFor() (*ztna.Client, error) {
	dialFn := s.dialer
	if dialFn == nil {
		var err error
		if dialFn, err = dial.New(s.cfg.Proxy); err != nil {
			return nil, err
		}
	}
	if s.cfg.DeviceID == "" {
		return nil, errors.New("缺少 device_id：它决定授信终端绑的是哪台设备，" +
			"应由服务进程首次启动时生成并写回配置文件")
	}
	// 指纹在加载时就校验过了，这里再解析一次拿到定长数组。
	pins, err := s.cfg.NodeSPKIPins()
	if err != nil {
		return nil, err
	}
	return ztna.New(ztna.Options{
		Server:           s.cfg.Server,
		DialAddr:         s.cfg.ConnectAddr(),
		Dial:             dialFn,
		Username:         s.cred.username,
		Password:         s.cred.password,
		LoginDomain:      s.cfg.LoginDomain,
		DeviceID:         s.cfg.DeviceID,
		Logf:             log.Printf,
		ControlRootCAs:   s.controlRootCAs,
		NodeSPKIPins:     pins,
		ReconnectBackoff: s.reconnectBackoff,
	})
}

func (s *Service) ResourcesJSON(limit int) ([]byte, error) {
	sess := s.sessionSnapshot.Load()
	if sess == nil {
		return nil, ztna.ErrResourcesUnavailable
	}
	view, err := sess.Resources()
	if err != nil {
		return nil, err
	}
	r := ipc.Resources{IP: make([]ipc.IPResource, len(view.IP)), TCPDomains: make([]ipc.TCPDomainResource, len(view.TCPDomains))}
	for i, rule := range view.IP {
		r.IP[i] = ipc.IPResource{Prefix: rule.Prefix, Protocol: rule.Protocol.String(), Ports: rule.Ports}
	}
	for i, rule := range view.TCPDomains {
		r.TCPDomains[i] = ipc.TCPDomainResource{Pattern: rule.Pattern, Ports: rule.Ports}
	}
	if view.DNS[0].IsValid() {
		r.DNS.Primary = view.DNS[0].String()
	}
	if view.DNS[1].IsValid() {
		r.DNS.Secondary = view.DNS[1].String()
	}
	return ipc.EncodeResources(r, limit)
}
