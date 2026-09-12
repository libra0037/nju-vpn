package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libra0037/nju-vpn/internal/config"
	"github.com/libra0037/nju-vpn/internal/dial"
	"github.com/libra0037/nju-vpn/internal/ipc"
	"github.com/libra0037/nju-vpn/internal/vpn"
	"github.com/libra0037/nju-vpn/internal/wireguard"
)

// ErrNotRunning 表示服务进程还没有建立隧道。
var ErrNotRunning = errors.New("隧道未运行")

// ErrBadState 表示当前状态不允许该操作（例如隧道已经建立时又敲 start）。
// 这是客户端用法问题，不是服务端故障，IPC 层据此回 409 而不是 500。
var ErrBadState = errors.New("当前状态不允许该操作")

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
	cmdTunnelRetry
	cmdSetPeer
)

type command struct {
	kind  commandKind
	arg   string
	gen   uint64
	err   error
	reply chan error
}

// credentials 是一次登录要用的三样东西。
//
// 配置文件里的口令只是初始值：`start` 可以带上本次输入的口令，服务进程把
// 它留在这里，供后续的重新登录（error 后重新 start、重连后重登）复用。
// 全程不落盘、不进 argv、不进日志。
type credentials struct {
	username string
	password string
	totp     string
}

// Service 持有一次隧道连接的全部资源。
//
// 所有会改状态的操作都在 loop 这一个协程里执行：调用方把命令放进 cmds，
// 等一个回复。这样就不需要在持锁状态下做网络 I/O——旧实现在 Start 全程
// 持有互斥锁，网络一慢，退出路径的登出就永远拿不到锁。
type Service struct {
	cfg    *config.Config
	status *statusStore

	// cred 只在 actor 协程里读写，不需要加锁。
	cred credentials

	cmds      chan *command
	closed    chan struct{}
	actorDone chan struct{}
	closeOnce sync.Once

	mu       sync.Mutex
	opCancel context.CancelFunc
	// device 由 actor 协程写、只读查询（wg-stats）读。它只是指针交换，
	// 用 atomic.Pointer 比"谁在锁里访问"的约定更省心。
	device atomic.Pointer[wireguard.Device]

	// 以下字段只在 actor 协程里访问，不需要加锁。
	// dialer 与 clientOptions 是测试注入点。
	//
	// 注意注入的是"额外的 Options 字段"，不是整个 Client 的构造方式：
	// Server / DialAddr / Dial 这些生产接线仍然由 start 算出来，测试能覆盖到
	//（以前整体替换构造方式，server_ip → DialAddr 这条线根本没进过测试）。
	dialer        vpn.DialFunc
	clientOptions func(*vpn.Options)
	client        *vpn.Client
	session       *vpn.Session
	runCancel     context.CancelFunc
	gen           uint64
	pendingAuth   *vpn.AuthRequiredError
}

// New 构造服务对象并启动命令循环。
func New(cfg *config.Config) *Service {
	s := &Service{
		cfg:    cfg,
		status: newStatusStore(identityOf(cfg)),
		cred: credentials{
			username: cfg.Username,
			password: cfg.Password,
			totp:     cfg.TOTPSecret,
		},
		cmds:      make(chan *command),
		closed:    make(chan struct{}),
		actorDone: make(chan struct{}),
	}
	go s.loop()
	return s
}

// identityOf 组装实例身份，只在启动时算一次。
//
// 端点规则与 cmd 层的 endpointOf 相同：显式配置优先，否则按配置文件的
// 路径派生；两处都委托给 ipc 包，规则只有一份。
func identityOf(cfg *config.Config) Identity {
	endpoint := cfg.IPC.Endpoint
	if endpoint == "" {
		endpoint = ipc.EndpointFor(cfg.SourcePath())
	}
	return Identity{
		PID:        os.Getpid(),
		ConfigPath: cfg.SourcePath(),
		Endpoint:   endpoint,
		Username:   cfg.Username,
	}
}

// Status 返回当前状态快照。它不经过 actor，永远立即可用。
func (s *Service) Status() Status { return s.status.Get() }

// Identity 返回实例身份。
func (s *Service) Identity() Identity { return s.status.Get().Identity }

// Done 在服务对象开始收尾（Close 被调用）时关闭。
//
// 服务进程的主循环靠它解阻塞：Close 可能来自任何一处（信号、shutdown
// 命令、调用方的 defer），监听套接字必须跟着一起收掉。
func (s *Service) Done() <-chan struct{} { return s.closed }

// SetDialer 替换出站拨号函数（测试用）。
//
// 必须在第一次调用 Start 之前设置：真正读取它的只有 actor 协程，
// 而第一次命令的发送建立了 happens-before 关系。
func (s *Service) SetDialer(f vpn.DialFunc) { s.dialer = f }

// SetClientOptions 覆盖客户端构造时的额外字段（测试用，例如注入假的
// portal HTTP 客户端与隧道拨号）。
func (s *Service) SetClientOptions(f func(*vpn.Options)) { s.clientOptions = f }

// Start 建立隧道。
//
// 若服务端要求二次验证，会切到 auth_pending 并返回 ErrAuthRequired，
// 由调用方通过 Auth 提交验证码后继续。
func (s *Service) Start() error {
	return s.call(&command{kind: cmdStart})
}

// StartWithPassword 建立隧道，并使用本次提供的口令。
//
// 口令只留在内存里：配置文件里不写口令时，CLI 在终端现问一遍再这样传进来。
func (s *Service) StartWithPassword(password string) error {
	return s.call(&command{kind: cmdStart, arg: password})
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

// WireGuardStats 返回承载层的收发统计。
//
// 它不经过 actor：只读设备状态，与命令执行无关，用读锁保护字段快照即可。
func (s *Service) WireGuardStats() ([]wireguard.PeerStats, error) {
	dev := s.currentDevice()
	if dev == nil {
		return nil, ErrNotRunning
	}
	return dev.Stats()
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

// setDevice 记录承载设备。actor 协程与只读查询都会访问这个字段。
func (s *Service) setDevice(dev *wireguard.Device) {
	s.device.Store(dev)
}

// currentDevice 返回当前承载设备，可能为 nil。
func (s *Service) currentDevice() *wireguard.Device {
	return s.device.Load()
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

	// 退出期间不再执行新命令：Close 已经走过登出，此时再建隧道会留下
	// 没人管的会话。cmdTunnelDown 例外——它是隧道协程的收尾报告，
	// 丢掉它会让状态卡在 up。
	if cmd.kind != cmdTunnelDown {
		select {
		case <-s.closed:
			reply(ErrShuttingDown)
			return
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
			s.status.set(StateError, err.Error())
			reply(err)
		}
	}()

	var err error
	switch cmd.kind {
	case cmdStart:
		err = s.start(ctx, cmd.arg)
	case cmdAuth:
		err = s.auth(ctx, cmd.arg)
	case cmdStop:
		err = s.stop()
	case cmdTunnelDown:
		err = s.tunnelDown(cmd.gen, cmd.err)
	case cmdTunnelRetry:
		err = s.tunnelRetry(cmd.gen, cmd.arg, cmd.err)
	case cmdSetPeer:
		err = s.setPeer(cmd.arg)
	default:
		err = fmt.Errorf("未知命令 %d", cmd.kind)
	}
	reply(err)
}

// start 建立隧道。
//
// password 非空时替换内存里的口令：配置里不写口令的部署靠它把口令带进来。
func (s *Service) start(ctx context.Context, password string) error {
	cur := s.status.Get().State
	switch cur {
	case StateAuthPending:
		// 等待验证码时再次 start，意味着用户没收到码、想重新要一条。
		// 旧 TwfID 上重复请求会被服务端拒绝，所以丢弃旧会话重新登录。
		s.teardown("重新登录")
	case StateIdle, StateError:
		s.teardown("")
	default:
		return fmt.Errorf("%w: 当前状态是 %s", ErrBadState, cur)
	}

	if password != "" {
		s.cred.password = password
	}
	// 口令可能从终端带进来换行，去掉首尾空白再用于登录。
	s.cred.password = strings.TrimSpace(s.cred.password)
	if s.cred.password == "" {
		return s.fail(errors.New("没有可用的口令：配置文件里的 password 为空，且本次请求没有带上；" +
			"请在 `njuvpn start` 的提示下输入"))
	}
	if s.cred.username == "" {
		return s.fail(errors.New("配置文件里缺少 username"))
	}

	s.status.set(StateLoggingIn, "正在登录")

	var err error
	var dialFn vpn.DialFunc
	if s.dialer != nil {
		dialFn = s.dialer
	} else {
		dialFn, err = dial.New(s.cfg.Proxy)
	}
	if err != nil {
		return s.fail(err)
	}
	opts := vpn.Options{
		Server:   s.cfg.ServerAddr(),
		DialAddr: s.cfg.DialAddr(),
		Dial:     dialFn,
	}
	if s.clientOptions != nil {
		s.clientOptions(&opts)
	}
	client := vpn.New(opts)
	if s.client != nil {
		s.client.CloseIdleConnections()
	}
	s.client = client

	trace := &vpn.Trace{}
	sess, err := client.Connect(ctx, vpn.ConnectOptions{
		Username:   s.cred.username,
		Password:   s.cred.password,
		TOTPSecret: s.cred.totp,
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
		Username: s.cred.username,
		Password: s.cred.password,
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

	// 先落盘再动设备：反过来的话，写回失败时设备已经用上新公钥、
	// 内存里的配置还是旧的，隧道重建后又变回旧公钥——客户端表现为
	// "接不上"，而日志只说写文件失败。
	if path := s.cfg.SourcePath(); path != "" {
		if err := config.PersistPeerPublicKey(path, key.String()); err != nil {
			return fmt.Errorf("写回配置文件失败: %w", err)
		}
	}

	applied := false
	if dev := s.currentDevice(); dev != nil {
		if err := dev.SetPeer(key, net.ParseIP(s.cfg.WireGuard.PeerAddress)); err != nil {
			return err
		}
		applied = true
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
	s.status.set(StateConnecting, "正在建立承载")

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
	s.setDevice(dev)

	log.Printf("WireGuard 承载已启动: %s", s.bearerSummary(dev, peerKey))

	s.status.setAddresses(sess.ClientIP(), s.cfg.WireGuard.PeerAddress)
	// 先进入 up 再启动隧道协程：如果协程立刻就失败，
	// tunnelDown 必须能看到 up 才能正确收敛，否则这次失败会被忽略掉。
	s.status.set(StateUp, "隧道已建立")

	// 隧道协程的生命周期独立于本次命令：Stop/Close 通过 runCancel 结束它。
	runCtx, cancel := context.WithCancel(context.Background())
	s.runCancel = cancel
	s.gen++
	gen := s.gen
	go func() {
		defer func() {
			// 隧道协程没有命令层的 recover 保护：真崩了要收敛成一次
			// "隧道断开"，而不是带走整个进程（进程一死就没人登出了）。
			if r := recover(); r != nil {
				panicErr := fmt.Errorf("隧道协程内部错误: %v", r)
				log.Printf("%v\n%s", panicErr, debug.Stack())
				s.reportTunnelDown(gen, panicErr)
			}
		}()
		// 重连尝试每次都在退避前经 actor 上报：状态仍是 up（隧道对象还在），
		// 但说明文字会变成"正在重连"，用户不至于以为链路正常。
		err := sess.RunWithRetryNotify(runCtx, vpn.DefaultRetryPolicy(), func(attempt int, retryErr error) {
			s.reportTunnelRetry(gen, attempt, retryErr)
		})
		s.reportTunnelDown(gen, err)
	}()

	log.Printf("隧道已建立：校园网地址 %s，peer 地址 %s", sess.ClientIP(), s.cfg.WireGuard.PeerAddress)
	return nil
}

// reportTunnelRetry 上报一次重连尝试。
//
// 与 reportTunnelDown 一样必须经过 actor；这条只改说明文字，不改状态：
// 隧道对象还在，WireGuard 设备也还在，只是底层流断了正在重连。
func (s *Service) reportTunnelRetry(gen uint64, attempt int, err error) {
	select {
	case s.cmds <- &command{
		kind:  cmdTunnelRetry,
		arg:   strconv.Itoa(attempt),
		gen:   gen,
		err:   err,
		reply: make(chan error, 1),
	}:
	case <-s.closed:
	}
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
	s.status.set(StateError, detail)
	// 重连窗口已经用尽：进程还活着，但不会自己再登录一次（短信模式下重登
	// 要人输验证码）。把恢复命令写进日志，别让用户对着 error 猜。
	log.Printf("隧道已停止，等待人工恢复：njuvpn start（会重新登录一次）")
	return nil
}

// tunnelRetry 在状态里标出"正在重连"。
//
// 只改说明文字：状态仍是 up，因为隧道对象与承载层都还在，
// 重连成功后不需要重建它们。
func (s *Service) tunnelRetry(gen uint64, attemptText string, err error) error {
	if gen != s.gen {
		return nil
	}
	if s.status.Get().State != StateUp && s.status.Get().State != StateError {
		return nil
	}
	s.status.setDetail(fmt.Sprintf("隧道断开，正在重连（第 %s 次）: %v", attemptText, err))
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
// 日志里给的是设备实际监听的端口：配置走默认值，但以设备为准更可靠。
func (s *Service) bearerSummary(dev *wireguard.Device, peerKey wireguard.Key) string {
	port := s.cfg.WireGuard.ListenPort
	if actual, err := dev.ListenPort(); err == nil && actual > 0 {
		port = actual
	}
	listen := fmt.Sprintf("UDP %d", port)
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
		detail = s.pendingAuth.UserText() + "，请用上一条验证码执行 njuvpn auth <code>"
	case s.pendingAuth != nil && errors.Is(s.pendingAuth, vpn.ErrSMSTooMany):
		detail = "短信发送过于频繁，请稍后再试"
	case s.pendingAuth != nil:
		detail = s.pendingAuth.UserText() + "，请执行 njuvpn auth <code>"
	default:
		detail = "需要短信验证码，请执行 njuvpn auth <code>"
	}
	s.status.set(StateAuthPending, detail)
	return fmt.Errorf("%s: %w", detail, ErrAuthRequired)
}

// fail 收敛到 error 状态。只能在 actor 协程内调用。
func (s *Service) fail(err error) error {
	s.teardown("")
	s.status.set(StateError, err.Error())
	return err
}

// teardown 释放本次连接的全部资源并回到 idle。只能在 actor 协程内调用。
func (s *Service) teardown(detail string) {
	if s.runCancel != nil {
		s.runCancel()
		s.runCancel = nil
	}
	if dev := s.currentDevice(); dev != nil {
		dev.Close()
		s.setDevice(nil)
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
		s.status.set(StateIdle, detail)
	}
}
