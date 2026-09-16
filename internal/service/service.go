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

// ErrStopRequested 表示这条命令在排队期间用户已经请求断开，因此没有执行。
var ErrStopRequested = errors.New("已收到断开请求，这条命令没有执行")

// ErrEmptyCode 表示请求里没有验证码。属于客户端用法问题，IPC 层回 400。
var ErrEmptyCode = errors.New("验证码为空")

// closeGrace 是 Close 等待 actor 收尾的上限。正常收尾就是一次登出请求，
// 登出自身有 10 秒超时，所以这里给足余量但不无限等。
const closeGrace = 20 * time.Second

// authWaitTimeout 是等待验证码的上限。
//
// 用户在提示符前直接关掉终端时，进程会一直停在 auth_pending，学校侧那条
// "同一账号只允许一个客户端"的名额也跟着被占住。到点就登出，宁可让用户
// 重新 start 一次。
//
// 用变量而不是常量：测试要把它缩到百毫秒级才能覆盖到这条路径。
var authWaitTimeout = 10 * time.Minute

type commandKind int

const (
	cmdStart commandKind = iota
	cmdAuth
	cmdAuthTimeout
	cmdStop
	cmdTunnelDown
	cmdTunnelRetry
	cmdSetPeer
	cmdSetProxy
)

type command struct {
	kind commandKind
	arg  string
	gen  uint64
	// seq 是发起方自己的轮次。收方用它丢弃过期命令：等待验证码的计时器
	// 可能已经触发、命令正排在队列里，而那一轮早就收场了。
	seq   uint64
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

	// dev 在进程存活期间一直存在；会话是它上面的一次挂载。
	dev *wireguard.Device
	// peerKey / peerAddr 是接入方配置，启动时解析一次；
	// wg-peer 命令可以换掉 peerKey。
	peerKey  wireguard.Key
	peerAddr net.IP

	cmds      chan *command
	closed    chan struct{}
	actorDone chan struct{}
	closeOnce sync.Once

	mu       sync.Mutex
	opCancel context.CancelFunc
	// stopPending 记录"用户已经请求断开"。它不只打断正在执行的那条命令，
	// 还要让排队中的 start / auth 别在 stop 之后接着跑完——命令在 actor
	// 里串行，一次登录最坏三分多钟，等它跑完再断，用户看到的是
	// "stop 超时退出、隧道随后又被建起来"。
	stopPending atomic.Bool
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
	// authTimer 只在 auth_pending 期间有效，到点由 actor 收尾。
	authTimer *time.Timer
	// authSeq 是"等待验证码"的轮次，每次起停自增。计时器触发时把当时
	// 的轮次带进命令里，迟到的命令因此能被认出来并丢掉。
	authSeq uint64
}

// New 构造服务对象并启动命令循环。
//
// 承载设备在这里就建起来，而不是等到隧道握手成功：端口被占、私钥写错、
// peer 地址非法这类问题全部在进程启动时暴露。服务进程是 njuvpn start
// 拉起的，启动失败会立刻报给用户——不会白烧一条短信和一次建隧道配额。
func New(cfg *config.Config) (*Service, error) {
	privateKey, err := wireguard.ParseKey(cfg.WireGuard.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("wireguard.private_key: %w", err)
	}
	var peerKey wireguard.Key
	if cfg.WireGuard.PeerPublicKey != "" {
		if peerKey, err = wireguard.ParseKey(cfg.WireGuard.PeerPublicKey); err != nil {
			return nil, fmt.Errorf("wireguard.peer_public_key: %w", err)
		}
		// 全零公钥能通过 base64 解析，却不是合法的 x25519 公钥点。
		// 不拦住的话它会一路走到 SetPeer，客户端表现为永远握手失败。
		if peerKey.IsZero() {
			return nil, fmt.Errorf("wireguard.peer_public_key 是全零公钥，不是合法的 WireGuard 公钥")
		}
	}
	peerAddr := net.ParseIP(cfg.WireGuard.PeerAddress)
	// 只承载 IPv4：Mapper 与 allowed_ip 都按 /32 写。配置校验里也是这条规则，
	// 这里重复一次是因为 Config 也可能由调用方直接构造（测试、将来的嵌入场景）。
	if peerAddr == nil || peerAddr.To4() == nil {
		return nil, fmt.Errorf("wireguard.peer_address 必须是 IPv4 地址: %q", cfg.WireGuard.PeerAddress)
	}

	dev, err := wireguard.NewDevice(wireguard.DeviceOptions{
		MTU:        cfg.MTU,
		PrivateKey: privateKey,
		ListenPort: cfg.WireGuard.ListenPort,
		ListenHost: listenHost(cfg.WireGuard.ListenHost),
		Verbose:    cfg.Log.Level == "debug",
	})
	if err != nil {
		return nil, fmt.Errorf("启动 WireGuard 承载: %w", err)
	}

	s := &Service{
		cfg:    cfg,
		status: newStatusStore(identityOf(cfg)),
		dev:    dev,
		// 接入方公钥在启动时解析一次：写错了当场报错，而不是等用户
		// 输完验证码、占掉配额之后才告诉他。
		peerKey:  peerKey,
		peerAddr: peerAddr,
		cred: credentials{
			username: cfg.Username,
			password: cfg.Password,
			totp:     cfg.TOTPSecret,
		},
		cmds:      make(chan *command),
		closed:    make(chan struct{}),
		actorDone: make(chan struct{}),
	}
	s.setDevice(dev)
	go s.loop()
	return s, nil
}

// identityOf 组装实例身份，只在启动时算一次。
//
// 端点规则与 cmd 层的 endpointOf 共用 ipc.ResolveEndpoint：两处算错任何
// 一处，命令就会打到别的实例上去。
func identityOf(cfg *config.Config) Identity {
	return Identity{
		PID:        os.Getpid(),
		ConfigPath: cfg.SourcePath(),
		Endpoint:   ipc.ResolveEndpoint(cfg.IPC.Endpoint, cfg.SourcePath()),
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

// StartWithPassword 建立隧道，并使用本次提供的口令（空串表示沿用服务进程
// 内存里已有的那份，也就是配置文件里的或上一次 start 带来的）。
//
// 口令只留在内存里：配置文件里不写口令时，CLI 在终端现问一遍再这样传进来。
// 若服务端要求二次验证，会切到 auth_pending 并返回 ErrAuthRequired，
// 由调用方通过 Auth 提交验证码后继续。
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

// SetProxy 覆盖出站代理，供 CLI 在拉起服务进程之后立刻下发。
//
// 走命令通道而不是直接改配置结构：cfg 由 actor 读（start 时构造拨号
// 函数），从别的协程改就是数据竞争。
func (s *Service) SetProxy(proxy string) error {
	return s.call(&command{kind: cmdSetProxy, arg: proxy})
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
//
// 先打断正在进行的操作再排队：命令在 actor 里串行，而一次登录最坏要走
// 三分多钟（短信、退避重试），stop 的语义却是"现在就断"。被打断的 start
// 以取消收场，随后这条 stop 照常执行——用户不必转去手工杀进程，而手工杀
// 会跳过登出。
func (s *Service) Stop() error {
	s.stopPending.Store(true)
	s.cancelOp()
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

		// 设备是进程级资源，收尾完成后才关：上面那一步会登出，
		// 而 tunnelDown 之类的路径还在用它。
		if dev := s.currentDevice(); dev != nil {
			s.setDevice(nil)
			dev.Close()
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

	// 用户已经请求断开时，排队中的登录类命令不再执行：它们会在那条 stop
	// 之后接着登录、发短信、建隧道，用户看到的是"stop 报超时，可隧道后来
	// 又自己起来了"。stop 自己当然要放行，它正是来清这个标记的。
	if s.stopPending.Load() {
		switch cmd.kind {
		case cmdStart, cmdAuth:
			log.Printf("已收到断开请求，丢弃排队中的 %v 命令", cmd.kind)
			reply(ErrStopRequested)
			return
		}
	}

	var err error
	switch cmd.kind {
	case cmdStart:
		err = s.start(ctx, cmd.arg)
	case cmdAuth:
		err = s.auth(ctx, cmd.arg)
	case cmdAuthTimeout:
		err = s.authTimeout(cmd.seq)
	case cmdStop:
		err = s.stop()
	case cmdTunnelDown:
		err = s.tunnelDown(cmd.gen, cmd.err)
	case cmdTunnelRetry:
		err = s.tunnelRetry(cmd.gen, cmd.arg, cmd.err)
	case cmdSetPeer:
		err = s.setPeer(cmd.arg)
	case cmdSetProxy:
		err = s.setProxy(cmd.arg)
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
		return ErrEmptyCode
	}

	// 续用同一个服务端会话：先把待验证的会话从 s.session 上摘下来，
	// 否则 attach 会把"上一个会话"当成需要释放的对象，用同一个 TwfID
	// 去登出——那会把正在续用的会话一起杀掉（真机实测：登出成功后
	// 上行流立刻被服务端以 Shutdown 拒绝）。
	pending := s.session
	s.session = nil
	// 续用期间 Connect 若 panic（协议解析、封装库），会话对象就没人引用了，
	// TwfID 跟着丢失，服务端那条名额要等它自己超时才释放。正常路径上
	// attach 会先把新会话装上，这条恢复因此不会生效。
	defer func() {
		if s.session == nil && pending != nil {
			s.session = pending
		}
	}()

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
	s.stopAuthTimer()
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
	s.peerKey = key

	applied := false
	// 只有隧道在跑时才装到设备上：空闲时设备仍然监听，装了 peer 会让
	// 客户端握手成功却发不出任何包，比连不上更难查。
	if s.status.Get().State == StateUp {
		if err := s.applyPeer(); err != nil {
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

// setProxy 记录出站代理的覆盖值。
//
// 只在内存里改：配置文件仍是"这台机器上跑什么"的真相来源，而 -proxy 是
// 一次性的命令行覆盖（CLI 拉起服务进程时经 IPC 送进来）。
func (s *Service) setProxy(proxy string) error {
	if proxy == "" {
		return nil
	}
	s.cfg.Proxy = proxy
	log.Printf("出站代理已更新: %s", config.RedactProxy(proxy))
	return nil
}

// stop 断开隧道。
func (s *Service) stop() error {
	// 标记到这里就完成了使命：这条 stop 之后到达的命令都是新意图。
	s.stopPending.Store(false)
	if s.status.Get().State == StateIdle && s.session == nil {
		return ErrNotRunning
	}
	s.teardown("隧道已断开")
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

	// 只有 Mapper 依赖这次登录：校园网地址是服务端刚分配的。
	mapper, err := wireguard.NewMapper(net.ParseIP(s.cfg.WireGuard.PeerAddress), net.ParseIP(sess.ClientIP()))
	if err != nil {
		return s.fail(fmt.Errorf("地址映射: %w", err))
	}

	s.dev.SetSession(sess.Endpoint(), mapper)
	s.status.setAddresses(sess.ClientIP(), s.cfg.WireGuard.PeerAddress)
	// 先进入 up 再启动隧道协程：如果协程立刻就失败，
	// tunnelDown 必须能看到 up 才能正确收敛，否则这次失败会被忽略掉。
	s.status.setRetrying(false)
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

	// 放行客户端接入放在最后：上行通道由隧道协程注册，晚一步放行，
	// 客户端第一次握手就更可能落在"已经能收包"的时刻。
	if err := s.applyPeer(); err != nil {
		return s.fail(err)
	}

	log.Printf("隧道已建立：校园网地址 %s，peer 地址 %s", sess.ClientIP(), s.cfg.WireGuard.PeerAddress)
	return nil
}

// applyPeer 把接入方公钥装到承载设备上。
//
// 没配置 peer 公钥时什么都不做：设备照常监听，只是没人能接入。
func (s *Service) applyPeer() error {
	if s.peerKey.IsZero() {
		return nil
	}
	if err := s.dev.SetPeer(s.peerKey, s.peerAddr); err != nil {
		return fmt.Errorf("配置接入公钥: %w", err)
	}
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
	s.status.setRetrying(true)
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

// BearerSummary 描述承载层的监听状态，供服务进程启动时打一行日志。
//
// 日志里给的是设备实际监听的端口：配置走默认值，但以设备为准更可靠。
func (s *Service) BearerSummary() string {
	port := s.cfg.WireGuard.ListenPort
	if actual, err := s.dev.ListenPort(); err == nil && actual > 0 {
		port = actual
	}
	listen := fmt.Sprintf("UDP %d", port)
	scope := "仅本机（127.0.0.1）"
	if listenHost(s.cfg.WireGuard.ListenHost) == wireguard.ListenAll {
		scope = "全部网卡"
	}
	if s.peerKey.IsZero() {
		return fmt.Sprintf("%s（%s）已就绪；未配置 wireguard.peer_public_key，任何客户端都无法接入", listen, scope)
	}
	return fmt.Sprintf("%s（%s）已就绪，peer 地址 %s", listen, scope, s.cfg.WireGuard.PeerAddress)
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
		detail = "需要 TOTP 验证码"
	case s.pendingAuth != nil && errors.Is(s.pendingAuth, vpn.ErrSMSStillValid):
		// 冷却期内服务端不会重发，上一条验证码仍然有效——不能提示"已发送"，
		// 否则用户会一直等一条不会来的短信。
		detail = s.pendingAuth.UserText() + "（请用上一条验证码）"
	case s.pendingAuth != nil && errors.Is(s.pendingAuth, vpn.ErrSMSTooMany):
		detail = "短信发送过于频繁，请稍后再试"
	case s.pendingAuth != nil:
		detail = s.pendingAuth.UserText()
	default:
		detail = "需要短信验证码"
	}
	s.status.set(StateAuthPending, detail)
	s.startAuthTimer()
	return fmt.Errorf("%s: %w", detail, ErrAuthRequired)
}

// startAuthTimer 在等待验证码时启动上限。
//
// 每次进入 auth_pending 都重新计时：验证码输错后还能再输，不该被上一个
// 计时器打断。
func (s *Service) startAuthTimer() {
	s.stopAuthTimer()
	seq := s.authSeq
	s.authTimer = time.AfterFunc(authWaitTimeout, func() { s.reportAuthTimeout(seq) })
}

// stopAuthTimer 取消等待验证码的上限。
//
// 同时推进轮次：计时器可能已经触发、命令正排在队列里，推进之后那条
// 迟到的命令就能认出自己是过期的。
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
		// start 了），这条命令什么都不能动——以前它会在这里把新一轮的
		// auth_pending 直接拆掉。
		return nil
	}
	if s.status.Get().State != StateAuthPending {
		return nil // 已经不在等验证码，无事可做
	}
	s.teardown("")
	detail := fmt.Sprintf("等待验证码超过 %s，已登出；重新建立隧道请执行 njuvpn start",
		authWaitTimeout.Round(time.Minute))
	log.Print(detail)
	s.status.set(StateError, detail)
	return nil
}

// fail 收敛到 error 状态。只能在 actor 协程内调用。
func (s *Service) fail(err error) error {
	s.teardown("")
	s.status.set(StateError, err.Error())
	return err
}

// teardown 释放本次连接的全部资源并回到 idle。只能在 actor 协程内调用。
//
// 承载设备不在释放之列：它活到进程结束，这里只把这次会话从它上面摘掉。
//
// 返回登出时遇到的错误：会话本身已经释放，但服务端那边可能还占着名额，
// 调用方据此决定要不要在对外的说明里提一句。以前的实现只写日志，
// 于是 stop 回了一句"隧道已断开"，而学校侧那条名额其实还挂着。
func (s *Service) teardown(detail string) error {
	// 先停表再登出：登出最长 10 秒，而计时器到点会按"等验证码超时"
	// 收尾——那会把紧接着的一轮登录（用户重新 start）一起拆掉。
	s.stopAuthTimer()
	if s.runCancel != nil {
		s.runCancel()
		s.runCancel = nil
	}
	// 先摘 peer 再摘会话：设备还在监听，留着 peer 会让客户端握手成功，
	// 而它的包其实已经没有隧道可走。
	if err := s.dev.ClearPeer(); err != nil {
		log.Printf("摘除 WireGuard peer 时出错: %v", err)
	}
	s.dev.ClearSession()
	var logoutErr error
	if s.session != nil {
		// 用独立的超时上下文：退出路径上的 ctx 很可能已经被取消，
		// 而登出本身必须发出去。
		// 服务端已经没有这个会话不算错误——目标已经达成。
		if err := s.session.Close(context.Background()); err != nil && !errors.Is(err, vpn.ErrLogoutNoSession) {
			logoutErr = err
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
		if logoutErr != nil {
			detail = fmt.Sprintf("%s（登出未成功: %v，服务端名额可能仍被占用）", detail, logoutErr)
		}
		s.status.set(StateIdle, detail)
	}
	return logoutErr
}
