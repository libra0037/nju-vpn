package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"njuvpn/internal/config"
	"njuvpn/internal/dial"
	"njuvpn/internal/vpn"
	"njuvpn/internal/wireguard"
)

// ErrNotRunning 表示服务进程还没有建立隧道。
var ErrNotRunning = errors.New("隧道未运行")

// ErrAuthRequired 表示需要提交验证码才能继续。
var ErrAuthRequired = errors.New("需要二次验证")

// ErrShuttingDown 表示服务进程正在退出，不再接受新命令。
var ErrShuttingDown = errors.New("服务进程正在退出")

// closeGrace 是 Close 等待 actor 收尾的上限。正常收尾就是一次登出请求，
// 登出自身有 10 秒超时，所以这里给足余量但不无限等。
const closeGrace = 20 * time.Second

type commandKind int

const (
	cmdStart commandKind = iota
	cmdAuth
	cmdStop
	cmdTunnelDown
	cmdSetPeer
)

type command struct {
	kind  commandKind
	arg   string
	gen   uint64
	err   error
	reply chan error
}

// Service 持有一次隧道连接的全部资源。
//
// 所有会改状态的操作都在 loop 这一个协程里执行：调用方把命令放进 cmds，
// 等一个回复。这样就不需要在持锁状态下做网络 I/O——旧实现在 Start 全程
// 持有互斥锁，网络一慢，退出路径的登出就永远拿不到锁。
type Service struct {
	cfg    *config.Config
	status *statusStore

	cmds      chan *command
	closed    chan struct{}
	actorDone chan struct{}
	closeOnce sync.Once

	mu       sync.Mutex
	opCancel context.CancelFunc

	// 以下字段只在 actor 协程里访问，不需要加锁。
	clientFactory func(cfg *config.Config) (*vpn.Client, error)
	client        *vpn.Client
	session       *vpn.Session
	device        *wireguard.Device
	runCancel     context.CancelFunc
	gen           uint64
	pendingAuth   *vpn.AuthRequiredError
}

// New 构造服务对象并启动命令循环。
func New(cfg *config.Config) *Service {
	s := &Service{
		cfg:       cfg,
		status:    newStatusStore(),
		cmds:      make(chan *command),
		closed:    make(chan struct{}),
		actorDone: make(chan struct{}),
	}
	go s.loop()
	return s
}

// Status 返回当前状态快照。它不经过 actor，永远立即可用。
func (s *Service) Status() Status { return s.status.Get() }

// SetClientFactory 注入协议客户端的构造方式，供测试注入假的 portal 与隧道。
//
// 必须在第一次调用 Start 之前设置：真正读取它的只有 actor 协程，
// 而第一次命令的发送建立了 happens-before 关系。
func (s *Service) SetClientFactory(f func(cfg *config.Config) (*vpn.Client, error)) {
	s.clientFactory = f
}

// Start 建立隧道。
//
// 若服务端要求二次验证，会切到 auth_pending 并返回 ErrAuthRequired，
// 由调用方通过 Auth 提交验证码后继续。
func (s *Service) Start() error {
	return s.call(&command{kind: cmdStart})
}

// Auth 提交二次验证码。仅在 auth_pending 状态下有效。
func (s *Service) Auth(code string) error {
	return s.call(&command{kind: cmdAuth, arg: code})
}

// SetPeer 更新 WireGuard 接入方的公钥，并写回配置文件。
//
// 不需要重建隧道：校园网隧道与 WireGuard 设备各自独立。这样更换客户端
// 密钥（例如重新生成 Clash 配置）不必再登录一次、再花一条短信。
func (s *Service) SetPeer(publicKey string) error {
	return s.call(&command{kind: cmdSetPeer, arg: publicKey})
}

// Stop 断开隧道并释放资源。
func (s *Service) Stop() error {
	return s.call(&command{kind: cmdStop})
}

// Close 停止命令循环、释放资源并通知服务端登出。可安全重复调用。
//
// 与 Stop 的区别是不判断状态、不返回错误：进程退出路径必须执行它。
// 服务端同一账号只允许一个客户端，残留会话会导致后续建隧道被拒。
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
	})
}

// call 把命令交给 actor 并等回复。
func (s *Service) call(cmd *command) error {
	cmd.reply = make(chan error, 1)

	select {
	case s.cmds <- cmd:
	case <-s.closed:
		return ErrShuttingDown
	}

	select {
	case err := <-cmd.reply:
		return err
	case <-s.closed:
		return ErrShuttingDown
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
			return
		case cmd := <-s.cmds:
			s.dispatch(cmd)
		}
	}
}

// dispatch 执行一条命令。
//
// 这里是最外层panic 边界：任何一处未预料到的崩溃都会转成一次失败，
// 而不是带走整个进程——服务端的会话还开着，进程直接死掉就没人登出了。
func (s *Service) dispatch(cmd *command) {
	ctx, cancel := context.WithCancel(context.Background())
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

		if r := recover(); r != nil {
			err := fmt.Errorf("内部错误: %v", r)
			log.Printf("%v\n%s", err, debug.Stack())
			s.teardown("内部错误")
			_ = s.status.set(StateError, err.Error())
			reply(err)
		}
	}()

	var err error
	switch cmd.kind {
	case cmdStart:
		err = s.start(ctx)
	case cmdAuth:
		err = s.auth(ctx, cmd.arg)
	case cmdStop:
		err = s.stop()
	case cmdTunnelDown:
		err = s.tunnelDown(cmd.gen, cmd.err)
	case cmdSetPeer:
		err = s.setPeer(cmd.arg)
	default:
		err = fmt.Errorf("未知命令 %d", cmd.kind)
	}
	reply(err)
}

// start 建立隧道。
func (s *Service) start(ctx context.Context) error {
	cur := s.status.Get().State
	switch cur {
	case StateAuthPending:
		// 等待验证码时再次 start，意味着用户没收到码、想重新要一条。
		// 旧 TwfID 上重复请求会被服务端拒绝，所以丢弃旧会话重新登录。
		s.teardown("重新登录")
	case StateIdle, StateError:
		s.teardown("")
	default:
		return fmt.Errorf("当前状态是 %s，无法开始新的连接", cur)
	}

	if err := s.status.set(StateLoggingIn, "正在登录"); err != nil {
		return err
	}

	var err error
	client := (*vpn.Client)(nil)
	if s.clientFactory != nil {
		client, err = s.clientFactory(s.cfg)
	} else {
		var dialFn vpn.DialFunc
		dialFn, err = dial.New(s.cfg.Proxy)
		if err == nil {
			client = vpn.New(vpn.Options{
				Server:   s.cfg.ServerAddr(),
				DialAddr: s.cfg.DialAddr(),
				Dial:     dialFn,
			})
		}
	}
	if err != nil {
		return s.fail(err)
	}
	if s.client != nil {
		s.client.CloseIdleConnections()
	}
	s.client = client

	trace := &vpn.Trace{}
	sess, err := client.Connect(ctx, vpn.ConnectOptions{
		Username:   s.cfg.Username,
		Password:   s.cfg.Password,
		TOTPSecret: s.cfg.TOTPSecret,
		Trace:      trace,
	})
	// 失败时把各阶段打出来：否则远程排查只能看到最后一行错误，
	// 分不清是登录、取 token、还是建隧道出的问题。
	defer func() {
		if err != nil || sess == nil {
			logTrace(trace, err)
		}
	}()
	// 失败时也可能已经拿到 TwfID：会话必须留下来，否则没法登出，
	// 服务端就会一直挂着一个占名额的会话。
	s.attach(sess)
	if err != nil {
		if authErr, ok := vpn.AsAuthRequired(err); ok {
			s.pendingAuth = authErr
			return s.awaitAuth()
		}
		return s.fail(err)
	}

	s.pendingAuth = nil
	return s.finishConnect(sess)
}

// auth 提交二次验证码。
func (s *Service) auth(ctx context.Context, code string) error {
	cur := s.status.Get().State
	if cur != StateAuthPending || s.pendingAuth == nil || s.client == nil {
		return fmt.Errorf("当前状态是 %s，不需要验证码", cur)
	}
	if code == "" {
		return errors.New("验证码为空")
	}

	// 续用同一个服务端会话：先把待验证的会话从 s.session 上摘下来，
	// 否则 attach 会把"上一个会话"当成需要释放的对象，用同一个 TwfID
	// 去登出——那会把正在续用的会话一起杀掉（真机实测：登出成功后
	// 上行流立刻被服务端以 Shutdown 拒绝）。
	pending := s.session
	s.session = nil

	trace := &vpn.Trace{}
	sess, err := s.client.Connect(ctx, vpn.ConnectOptions{
		Username: s.cfg.Username,
		Password: s.cfg.Password,
		TwfID:    s.pendingAuth.TwfID,
		Code:     code,
		AuthKind: s.pendingAuth.Kind,
		Trace:    trace,
	})
	// 待验证会话本身没有本地连接，只需要释放资源，不能登出。
	if pending != nil {
		pending.CloseLocal()
	}
	defer func() {
		if err != nil || sess == nil {
			logTrace(trace, err)
		}
	}()
	s.attach(sess)
	if err != nil {
		// 验证码本身错了不该把整个会话打回 idle：TwfID 还有效，
		// 用户可以再输一次。这里保持 auth_pending 并带上原因。
		if vpn.IsAuthCodeError(err) {
			s.status.setDetail(err.Error())
			return err
		}
		if authErr, ok := vpn.AsAuthRequired(err); ok {
			s.pendingAuth = authErr
			return s.awaitAuth()
		}
		return s.fail(err)
	}

	s.pendingAuth = nil
	return s.finishConnect(sess)
}

// setPeer 更新 WireGuard 接入方的公钥。
//
// 即使隧道没建立也接受：配置写回后，下次 start 就会生效。
func (s *Service) setPeer(publicKey string) error {
	key, err := wireguard.ParseKey(strings.TrimSpace(publicKey))
	if err != nil {
		return fmt.Errorf("peer 公钥: %w", err)
	}

	applied := false
	if s.device != nil {
		if err := s.device.SetPeer(key, net.ParseIP(s.cfg.WireGuard.PeerAddress)); err != nil {
			return err
		}
		applied = true
	}

	if path := s.cfg.SourcePath(); path != "" {
		if err := config.PersistPeerPublicKey(path, key.String()); err != nil {
			return fmt.Errorf("写回配置文件失败: %w", err)
		}
	}
	s.cfg.WireGuard.PeerPublicKey = key.String()

	if applied {
		log.Printf("已更新 WireGuard peer: %s（隧道未重建）", key.String())
	} else {
		log.Printf("已记录 WireGuard peer: %s，将在下次建立隧道时生效", key.String())
	}
	return nil
}

// stop 断开隧道。
func (s *Service) stop() error {
	if s.status.Get().State == StateIdle && s.session == nil {
		return ErrNotRunning
	}
	s.teardown("已断开")
	return nil
}

// attach 接管一次连接的结果。
//
// 注意失败路径同样要接管：Connect 在部分失败时会返回带 TwfID 的会话，
// 只有拿着它才能把服务端的会话释放掉。
func (s *Service) attach(sess *vpn.Session) {
	if sess == nil {
		return
	}
	prev := s.session
	s.session = sess
	if prev == nil || prev == sess {
		return
	}

	// 两道保险：TwfID 相同说明是同一个服务端会话（例如二次验证续用），
	// 对它登出等于把当前会话一起关掉，只能释放本地资源。
	if prev.TwfID() != "" && prev.TwfID() == sess.TwfID() {
		log.Printf("新会话与上一个共用同一 TwfID，只释放本地资源，不登出")
		prev.CloseLocal()
		return
	}
	if err := prev.Close(context.Background()); err != nil && !errors.Is(err, vpn.ErrLogoutNoSession) {
		log.Printf("释放上一个会话: %v", err)
	}
}

// finishConnect 用一次成功的连接建立 WireGuard 承载。
func (s *Service) finishConnect(sess *vpn.Session) error {
	if err := s.status.set(StateConnecting, "正在建立承载"); err != nil {
		return s.fail(err)
	}

	mapper, err := wireguard.NewMapper(net.ParseIP(s.cfg.WireGuard.PeerAddress), net.ParseIP(sess.ClientIP()))
	if err != nil {
		return s.fail(fmt.Errorf("地址映射: %w", err))
	}

	privateKey, err := wireguard.ParseKey(s.cfg.WireGuard.PrivateKey)
	if err != nil {
		return s.fail(fmt.Errorf("wireguard.private_key: %w", err))
	}
	var peerKey wireguard.Key
	if s.cfg.WireGuard.PeerPublicKey != "" {
		peerKey, err = wireguard.ParseKey(s.cfg.WireGuard.PeerPublicKey)
		if err != nil {
			return s.fail(fmt.Errorf("wireguard.peer_public_key: %w", err))
		}
	}

	dev, err := wireguard.NewDevice(wireguard.DeviceOptions{
		MTU:           s.cfg.MTU,
		Endpoint:      sess.Endpoint(),
		Mapper:        mapper,
		PrivateKey:    privateKey,
		ListenPort:    s.cfg.WireGuard.ListenPort,
		ListenHost:    listenHost(s.cfg.WireGuard.ListenHost),
		PeerPublicKey: peerKey,
		PeerAddress:   net.ParseIP(s.cfg.WireGuard.PeerAddress),
		Verbose:       s.cfg.Log.Level == "debug",
	})
	if err != nil {
		return s.fail(fmt.Errorf("启动 WireGuard 承载: %w", err))
	}
	s.device = dev

	log.Printf("WireGuard 承载已启动: %s", s.bearerSummary(dev, peerKey))

	s.status.setAddresses(sess.ClientIP(), s.cfg.WireGuard.PeerAddress)
	// 先进入 up 再启动隧道协程：如果协程立刻就失败，
	// tunnelDown 必须能看到 up 才能正确收敛，否则这次失败会被忽略掉。
	if err := s.status.set(StateUp, "隧道已建立"); err != nil {
		return s.fail(err)
	}

	// 隧道协程的生命周期独立于本次命令：Stop/Close 通过 runCancel 结束它。
	runCtx, cancel := context.WithCancel(context.Background())
	s.runCancel = cancel
	s.gen++
	gen := s.gen
	go func() {
		err := sess.RunWithRetry(runCtx, vpn.DefaultRetryPolicy())
		s.reportTunnelDown(gen, err)
	}()

	log.Printf("隧道已建立：校园网地址 %s，peer 地址 %s", sess.ClientIP(), s.cfg.WireGuard.PeerAddress)
	return nil
}

// reportTunnelDown 把隧道协程的退出转成一条命令交给 actor。
//
// 必须经过 actor：直接改状态就会和正在执行的命令打架。
func (s *Service) reportTunnelDown(gen uint64, err error) {
	select {
	case s.cmds <- &command{kind: cmdTunnelDown, gen: gen, err: err, reply: make(chan error, 1)}:
	case <-s.closed:
	}
}

// tunnelDown 处理隧道运行期断开。
//
// 代次（gen）检查是必须的：Stop 之后旧协程可能还在退避重连，
// 它退出时新会话早就建立了，不做区分就会把新会话一起拆掉。
func (s *Service) tunnelDown(gen uint64, err error) error {
	if gen != s.gen {
		log.Printf("忽略过期隧道协程的退出（第 %d 代，当前第 %d 代）: %v", gen, s.gen, err)
		return nil
	}
	if s.status.Get().State != StateUp {
		log.Printf("隧道协程已退出（当前状态 %s）: %v", s.status.Get().State, err)
		return nil
	}

	log.Printf("隧道断开: %v", err)
	s.teardown("")
	detail := "隧道已断开"
	if err != nil {
		detail += ": " + err.Error()
	}
	_ = s.status.set(StateError, detail)
	return nil
}

// listenHost 解析配置里的监听范围，非法值在配置校验阶段已经拦下。
func listenHost(s string) wireguard.ListenHost {
	host, err := wireguard.ParseListenHost(s)
	if err != nil {
		return wireguard.ListenLoopback
	}
	return host
}

// bearerSummary 描述承载层的监听状态。
//
// 配置里端口写 0 时由系统分配，日志要给出真实端口而不是一个 0。
func (s *Service) bearerSummary(dev *wireguard.Device, peerKey wireguard.Key) string {
	port := s.cfg.WireGuard.ListenPort
	if actual, err := dev.ListenPort(); err == nil && actual > 0 {
		port = actual
	}
	listen := fmt.Sprintf("UDP %d", port)
	if port == 0 {
		listen = "UDP 端口由系统分配"
	}
	scope := "仅本机（127.0.0.1）"
	if listenHost(s.cfg.WireGuard.ListenHost) == wireguard.ListenAll {
		scope = "全部网卡"
	}
	if peerKey.IsZero() {
		return fmt.Sprintf("%s（%s）在监听，但没有配置 peer_public_key，任何客户端都无法接入", listen, scope)
	}
	return fmt.Sprintf("%s（%s），peer %s", listen, scope, s.cfg.WireGuard.PeerAddress)
}

// logTrace 把各阶段耗时与结果写进日志，供失败后定位。
func logTrace(trace *vpn.Trace, err error) {
	stages := trace.Stages()
	if len(stages) == 0 {
		return
	}
	log.Printf("连接阶段明细（最终错误: %v）:", err)
	for _, s := range stages {
		result := "OK"
		if s.Err != nil {
			result = s.Err.Error()
		}
		log.Printf("  %-20s %-10s %s", s.Name, s.Duration.Round(time.Millisecond), result)
	}
}

// awaitAuth 切到等待验证码状态。
func (s *Service) awaitAuth() error {
	var detail string
	kind := error(nil)
	if s.pendingAuth != nil {
		kind = s.pendingAuth.Kind
	}
	switch {
	case errors.Is(kind, vpn.ErrAuthTOTP):
		detail = "需要 TOTP 验证码，请执行 njuvpn auth <code>"
	case s.pendingAuth != nil && errors.Is(s.pendingAuth, vpn.ErrSMSSent):
		detail = "验证码已发送到手机，请执行 njuvpn auth <code>"
	case s.pendingAuth != nil && errors.Is(s.pendingAuth, vpn.ErrSMSStillValid):
		// 冷却期内服务端不会重发，上一条验证码仍然有效——不能提示"已发送"，
		// 否则用户会一直等一条不会来的短信。
		detail = vpn.UserMessage(s.pendingAuth) + "，请用上一条验证码执行 njuvpn auth <code>"
	case s.pendingAuth != nil && errors.Is(s.pendingAuth, vpn.ErrSMSTooMany):
		detail = "短信发送过于频繁，请稍后再试"
	case s.pendingAuth != nil:
		detail = vpn.UserMessage(s.pendingAuth) + "，请执行 njuvpn auth <code>"
	default:
		detail = "需要短信验证码，请执行 njuvpn auth <code>"
	}
	if err := s.status.set(StateAuthPending, detail); err != nil {
		return err
	}
	return fmt.Errorf("%s: %w", detail, ErrAuthRequired)
}

// fail 收敛到 error 状态。只能在 actor 协程内调用。
func (s *Service) fail(err error) error {
	s.teardown("")
	_ = s.status.set(StateError, err.Error())
	return err
}

// teardown 释放本次连接的全部资源并回到 idle。只能在 actor 协程内调用。
func (s *Service) teardown(detail string) {
	if s.runCancel != nil {
		s.runCancel()
		s.runCancel = nil
	}
	if s.device != nil {
		s.device.Close()
		s.device = nil
	}
	if s.session != nil {
		// 用独立的超时上下文：退出路径上的 ctx 很可能已经被取消，
		// 而登出本身必须发出去。
		// 服务端已经没有这个会话不算错误——目标已经达成。
		if err := s.session.Close(context.Background()); err != nil && !errors.Is(err, vpn.ErrLogoutNoSession) {
			log.Printf("释放会话时出错: %v", err)
		}
		s.session = nil
	}
	if s.client != nil {
		s.client.CloseIdleConnections()
	}
	s.pendingAuth = nil
	s.status.clearAddresses()

	if s.status.Get().State != StateIdle {
		if detail == "" {
			detail = "已断开"
		}
		if err := s.status.set(StateIdle, detail); err != nil {
			log.Printf("状态收敛失败: %v", err)
		}
	}
}

// WaitReady 等待隧道进入 up 状态，用于测试和启动检查。
func (s *Service) WaitReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.status.Get().State == StateUp {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("等待隧道就绪超时（当前状态 %s）", s.status.Get().State)
}
