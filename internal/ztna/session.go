package ztna

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/libra0037/nju-vpn/internal/dial"
	"github.com/libra0037/nju-vpn/internal/l3"
)

// Options 是协议层的固定参数（来自配置）。
type Options struct {
	Server      string // 用于 Host 头与 SNI 的名字
	DialAddr    string // 实际连接地址
	Dial        dial.DialFunc
	Username    string
	Password    string
	LoginDomain string
	DeviceID    string
	Logf        func(format string, args ...any)
	// ControlRootCAs 为离线测试注入受控信任；nil 使用系统信任链。
	// 始终验证证书链与名称，不接受配置文件控制这项测试依赖。
	ControlRootCAs *x509.CertPool
	// NodeSPKIPins 是配置边界已解析的只读 SPKI SHA-256 白名单。
	NodeSPKIPins     [][sha256.Size]byte
	ReconnectBackoff time.Duration
}

// Client 持有共享校园登录参数；Connect 只登录并发布资源。
type Client struct {
	opts Options
	pins *nodeSPKIPins
}

func New(opts Options) (*Client, error) {
	if opts.Server == "" || opts.DialAddr == "" || opts.Dial == nil || opts.DeviceID == "" {
		return nil, &ProtocolError{What: "缺少服务端地址、拨号实现或设备标识"}
	}
	if len(opts.NodeSPKIPins) == 0 {
		return nil, ErrNodeUntrusted
	}
	if len(opts.NodeSPKIPins) > 16 {
		return nil, &ProtocolError{What: "SPKI 白名单超过上限"}
	}
	if opts.ControlRootCAs != nil {
		opts.ControlRootCAs = opts.ControlRootCAs.Clone()
	}
	if opts.ReconnectBackoff == 0 {
		opts.ReconnectBackoff = time.Second
	}
	if opts.ReconnectBackoff < 0 {
		return nil, &ProtocolError{What: "重连退避须为正数"}
	}
	pins := newNodeSPKIPins(opts.NodeSPKIPins)
	opts.NodeSPKIPins = nil // 校验器拥有独立快照。
	return &Client{opts: opts, pins: pins}, nil
}

func (c *Client) logf(format string, args ...any) {
	if c.opts.Logf != nil {
		c.opts.Logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

func (c *Client) newControl(deviceID string) (*control, error) {
	return newControl(controlOptions{
		Server:   c.opts.Server,
		DialAddr: c.opts.DialAddr,
		Dial:     c.opts.Dial,
		DeviceID: deviceID,
		Debug:    func(s string) { c.logf("%s", s) },
		RootCAs:  c.opts.ControlRootCAs,
	})
}

// ConnectOptions 是每次连接的可变参数。
type ConnectOptions struct {
	// Password 为空时用配置里的口令。
	Password string
}

// Session 是一次校园网会话。
//
// 它可能停在"等待验证码"的半完成状态：这时 Connect 同时返回会话和
// ErrAuthRequired，调用方要么调用 Auth 继续，要么 Close 释放——绝不能
// 丢掉会话，否则服务端的在线名额不会释放。
type Session struct {
	client *Client
	ctrl   *control
	table  *resourceTable
	ep     *l3.Endpoint

	password string
	username string

	step       authStep
	withAuthID bool
	ticket     string

	node    string
	l3MTU   int
	signKey []byte
	// devicesOnly 表示这次登录只用于授信终端操作，不建隧道。
	devicesOnly bool

	mu             sync.Mutex
	active         *tunnelConn
	closed         bool
	failure        error
	tcpConnections map[*TCPConn]struct{}
	dials          sync.WaitGroup
	ctx            context.Context
	cancel         context.CancelFunc
	runDone        chan struct{}

	closeOnce sync.Once
	closeErr  error
}

// Connect 登录并取资源。L3 由 StartL3 单独启动；需要验证码时保留会话。
func (c *Client) Connect(ctx context.Context, co ConnectOptions) (*Session, error) {
	s, err := c.newSession(ctx, co.Password, false)
	if err != nil {
		return s, err
	}
	if err := s.prepare(ctx); err != nil {
		_ = s.Close(context.Background())
		return s, err
	}
	return s, nil
}

// newSession 完成到"认证链走完"为止的登录：口令登录、上报环境、按服务名往
// 下走。devicesOnly 表示这次登录只为授信终端操作服务，不取资源也不建隧道。
//
// 两条入口（建隧道 / 只做授信终端）的差别只有这一处，其余必须逐字一致：
// 以前它们是两份拷贝，改漏一处就会出现"某条路径忘了保留会话"这种只在一个
// 入口上出现的故障。
func (c *Client) newSession(ctx context.Context, password string, devicesOnly bool) (*Session, error) {
	if password == "" {
		password = c.opts.Password
	}
	if c.opts.DeviceID == "" {
		return nil, &ProtocolError{What: "缺少设备标识"}
	}
	ctrl, err := c.newControl(c.opts.DeviceID)
	if err != nil {
		return nil, err
	}
	ownedCtx, cancel := context.WithCancel(context.Background())
	s := &Session{client: c, ctrl: ctrl, password: password, ep: l3.New(), devicesOnly: devicesOnly, ctx: ownedCtx, cancel: cancel, tcpConnections: make(map[*TCPConn]struct{})}

	if err := s.beginLogin(ctx); err != nil {
		_ = s.Close(context.Background())
		return s, err
	}
	if s.step.Service != "" {
		return s, &ErrAuthRequired{Kind: s.step.Service, Hint: s.smsHint(ctx)}
	}
	return s, nil
}

// beginLogin 走到认证链这一步：口令登录 + 上报环境 + 按服务名往下走。
func (s *Session) beginLogin(ctx context.Context) error {
	if err := s.ctrl.manifest(ctx); err != nil {
		// manifest 只用来取服务端版本，失败不致命。
		s.client.logf("读取服务端信息失败（继续）: %v", err)
	}
	cfg, err := s.ctrl.authConfig(ctx, true)
	if err != nil {
		return err
	}
	if cfg.IsLogin {
		s.client.logf("服务端认为本会话已登录，跳过口令")
		return nil
	}
	method, err := pickPasswordMethod(cfg.Methods, s.client.opts.LoginDomain)
	if err != nil {
		return err
	}
	res, err := s.ctrl.passwordLogin(ctx, s.client.opts.Username, s.password, method.LoginDomain, cfg.AntiReplayRand)
	if err != nil {
		return err
	}
	s.ticket = res.Ticket
	if err := s.ctrl.reportEnv(ctx, res.Ticket); err != nil {
		return err
	}
	s.step = authStep{Service: res.NextService}
	return s.continueAuth(ctx)
}

// continueAuth 按服务端给的服务名往下走。目前只有短信需要用户参与。
//
// 走到需要用户参与的那一步不算错误：置好 s.step 就返回 nil，调用方看
// s.step.Service 就知道该等验证码。把"需要验证码"表达成错误会让 Connect 在
// 把它交给调用方之前先 Close——而 Close 内含登出，半完成的会话就此作废。
func (s *Session) continueAuth(ctx context.Context) error {
	for i := 0; i < 8; i++ {
		switch s.step.Service {
		case "":
			return nil
		case "auth/authCheck":
			step, err := s.ctrl.authCheck(ctx)
			if err != nil {
				return err
			}
			s.step = step
		case "auth/sms":
			s.withAuthID = s.step.AuthID != ""
			return nil
		default:
			return &ProtocolError{What: "不支持的二次验证方式"}
		}
	}
	return &ProtocolError{What: "认证链过长"}
}

// Auth 提交验证码并继续。成功后资源就绪，端点由调用方分别启动。
func (s *Session) Auth(ctx context.Context, code string) error {
	if s.step.Service != "auth/sms" {
		return &ProtocolError{What: "当前不需要验证码"}
	}
	step, err := s.ctrl.submitSMS(ctx, s.step.AuthID, s.withAuthID, code)
	if err != nil {
		return err
	}
	s.step = step
	if err := s.continueAuth(ctx); err != nil {
		return err
	}
	// 服务端既没报错也没放行（例如把这次的码当成过期）：会话还活着，让用户
	// 再输一次，别把它拆掉。
	if s.step.Service != "" {
		return &ErrAuthRequired{Kind: s.step.Service, Hint: s.smsHint(ctx)}
	}
	if s.devicesOnly {
		return nil
	}
	return s.prepare(ctx)
}

// SMSHint 返回手机号脱敏后的提示；服务端答不上来时给一句兜底文案。
func (s *Session) SMSHint(ctx context.Context) string { return s.smsHint(ctx) }

// SMSPrompt 触发短信并返回本地固定文案。
func (s *Session) SMSPrompt(ctx context.Context) (string, error) {
	return s.ctrl.sendSMS(ctx, s.step.AuthID, s.withAuthID)
}

func (s *Session) smsHint(ctx context.Context) string {
	phones, err := s.ctrl.phoneNumber(ctx, s.step.AuthID)
	if err != nil || len(phones) == 0 {
		return "服务端要求短信验证码"
	}
	return fmt.Sprintf("验证码将发送至 %s", maskPhone(phones[0]))
}

// prepare 只建立共享登录资源，发布后不修改。
func (s *Session) prepare(ctx context.Context) error {
	info, err := s.ctrl.onlineInfo(ctx)
	if err != nil {
		return err
	}
	s.username = info.Username

	raw, err := s.ctrl.clientResource(ctx)
	if err != nil {
		return err
	}
	table, stats, err := parseResourceTable(raw, s.client.opts.Server)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return context.Canceled
	}
	s.signKey = randomSignKey()
	s.table = table
	s.mu.Unlock()
	s.client.logf("资源表: %d 条 IPv4 规则，%d 条 TCP 域名规则，%d 个节点", len(table.ipRules), len(table.domainRules), len(table.candidateNodes(table.majorGroup)))
	s.client.logf("资源解析跳过: 应用 %d，空标识 %d，协议 %d，地址 %d，端口 %d，非法 IP %d，不支持 IP %d，缺少建连 IP %d，节点 %d", stats.skippedApps, stats.emptyAppID, stats.unsupportedProtocol, stats.unsupportedAddress, stats.badPorts, stats.badIPs, stats.unsupportedIPs, stats.missingDialIPs, stats.badNodes)
	return nil
}

// StartL3 建立 IPv4 通道；MTU 只约束这一端点。调用方串行启停 L3。
func (s *Session) StartL3(ctx context.Context, mtu int) error {
	if mtu < ipv4MinHeader || mtu > 65535 {
		return &ProtocolError{What: "MTU 超出 IPv4 长度范围"}
	}
	s.mu.Lock()
	if s.closed || s.ctx.Err() != nil || s.table == nil {
		s.mu.Unlock()
		return ErrResourcesUnavailable
	}
	if s.active != nil || s.runDone != nil {
		s.mu.Unlock()
		return errors.New("L3 任务已启动")
	}
	s.l3MTU = mtu
	table := s.table
	s.dials.Add(1)
	s.mu.Unlock()
	defer s.dials.Done()
	ownedCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.ctx, cancel)
	defer func() { stop(); cancel() }()
	ctx = ownedCtx

	node, tlsConn, err := probeNodes(ctx, func(ctx context.Context, node string) (*tls.Conn, error) {
		return dialNodeTLS(ctx, s.tunnelOptions(node))
	}, table.candidateNodes(table.majorGroup), 6*time.Second)
	if err != nil {
		return err
	}
	s.node = node

	conn, err := handshakeTunnel(ctx, s.tunnelOptions(s.node), tlsConn)
	if err != nil {
		var gone *ErrSessionGone
		if errors.As(err, &gone) {
			s.invalidate(gone)
		}
		return err
	}
	s.mu.Lock()
	if s.closed || s.ctx.Err() != nil || ctx.Err() != nil {
		s.mu.Unlock()
		conn.Close()
		return context.Canceled
	}
	s.active = conn
	conn.start()
	s.mu.Unlock()
	s.client.logf("隧道连接已建立")
	return nil
}

func (s *Session) tunnelOptions(node string) tunnelOptions {
	return tunnelOptions{
		Node:     node,
		Server:   s.client.opts.Server,
		Dial:     s.client.opts.Dial,
		Table:    s.table,
		Endpoint: s.ep,
		SID:      s.sid(),
		DeviceID: s.client.opts.DeviceID,
		SignKey:  s.signKey,
		Logf:     s.client.logf,
		Pins:     s.client.pins,
		MTU:      s.l3MTU,
	}
}

// sid 是隧道握手用的会话标识：服务端把它下发在 sid cookie 里。
func (s *Session) sid() string {
	for _, c := range s.ctrl.cookies() {
		if c.Name == "sid" {
			return c.Value
		}
	}
	return ""
}

// ClientIP 返回服务端分配的校园网地址；还没建立隧道时返回 nil。
func (s *Session) ClientIP() net.IP {
	s.mu.Lock()
	conn := s.active
	s.mu.Unlock()
	if conn == nil {
		return nil
	}
	return conn.VIP()
}

// Endpoint 返回承载层要用的上下行通道。
func (s *Session) Endpoint() *l3.Endpoint { return s.ep }

// LinkEvents 报告运行期的链路事件。两个回调都可能从隧道自己的协程里
// 被调用，实现必须立刻返回：服务进程在这里只是往命令通道投一条消息，
// 任何阻塞都会拖住重连。
type LinkEvents struct {
	// Dropped 在连接断开、准备重连时调用，err 是断开原因。
	Dropped func(attempt int, err error)
	// Restored 在重连成功、链路恢复时调用。
	Restored func()
}

// 重连策略：断线后按退避重试，连续失败到上限才放弃。
//
// 上限是必须的：服务端把会话踢掉之后，再怎么重连也连不上，无限重试只会
// 让"隧道其实已经死了"这件事一直不显形。放弃时把错误交回上层，由它决定
// 要不要重新登录一次（那可能需要用户再输一次验证码）。
//
// 上限是全局的，不是"每个节点各来一遍"：节点列表可能很长，逐个试过去要等
// 很久，而"会话已死"这种情况在每个节点上都会失败。每次重连换下一个候选
// 节点，连续失败 maxReconnectFailures 次（含首次尝试当前节点）就放弃。
const (
	maxReconnectFailures = 3
	maxReconnectBackoff  = 30 * time.Second
)

// Run 维持隧道：连接断了就重连，直到 ctx 结束或者重连连续失败到上限。
//
// 重连用的还是本次登录拿到的会话（SID 与资源表都没变），因此不必重新
// 认证——短信模式下这一点很值钱：重连不花验证码，也不占新的名额。
//
// 节点按登录时那份候选列表轮换：失败一次就换下一个地址试。原先只对同一个
// 地址退避重试，选中的节点重启或维护期间三次失败就把整条隧道判死，用户得
// 重新登录（短信模式下还要再花一条验证码），而资源表里其他节点可能一直是
// 好的。
func (s *Session) Run(ctx context.Context, events LinkEvents) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return context.Canceled
	}
	if s.runDone != nil {
		s.mu.Unlock()
		return errors.New("会话运行任务已经启动")
	}
	s.runDone = make(chan struct{})
	done := s.runDone
	ownedCtx, cancel := context.WithCancel(s.ctx)
	s.mu.Unlock()
	stop := context.AfterFunc(ctx, cancel)
	defer func() { stop(); cancel(); close(done) }()
	ctx = ownedCtx
	backoff := s.client.opts.ReconnectBackoff
	attempt := 0
	failures := 0
	for {
		s.mu.Lock()
		conn := s.active
		s.mu.Unlock()
		if conn == nil {
			return fmt.Errorf("隧道未建立")
		}
		select {
		case <-ctx.Done():
			conn.Close()
			return ctx.Err()
		case <-conn.Done():
		}
		conn.Close()
		if ctx.Err() != nil {
			return ctx.Err()
		}

		var gone *ErrSessionGone
		if errors.As(conn.Err(), &gone) {
			s.invalidate(gone)
			return gone
		}
		attempt++
		if events.Dropped != nil {
			events.Dropped(attempt, conn.Err())
		}

		var reconnected *tunnelConn
		var lastErr error
		nodes := s.reconnectNodes()
		next := 0
		for reconnected == nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			node := nodes[next%len(nodes)]
			next++
			reconnected, lastErr = dialTunnel(ctx, s.tunnelOptions(node))
			if reconnected != nil {
				// 发布前还会在会话锁内检查关闭与取消。
				break
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.As(lastErr, &gone) {
				s.invalidate(gone)
				return gone
			}
			failures++
			if failures >= maxReconnectFailures {
				s.mu.Lock()
				s.active = nil
				s.mu.Unlock()
				return fmt.Errorf("重连失败 %d 次: %w", failures, lastErr)
			}
			if backoff < maxReconnectBackoff {
				backoff *= 2
			}
		}

		s.mu.Lock()
		if s.closed || s.ctx.Err() != nil || ctx.Err() != nil {
			s.mu.Unlock()
			reconnected.Close()
			return context.Canceled
		}
		s.active = reconnected
		s.node = reconnected.node
		reconnected.start()
		s.mu.Unlock()
		s.client.logf("隧道连接已建立")
		backoff = s.client.opts.ReconnectBackoff
		attempt = 0
		failures = 0
		if events.Restored != nil {
			events.Restored()
		}
	}
}

// reconnectNodes 返回重连时依次尝试的节点：当前节点优先，其余按资源表里
// 的候选顺序排后面。列表非空（prepare 里至少选中过一个节点）。
func (s *Session) reconnectNodes() []string {
	out := []string{s.node}
	if s.table == nil {
		return out
	}
	seen := map[string]bool{s.node: true}
	for _, addr := range s.table.candidateNodes(s.table.majorGroup) {
		if seen[addr] {
			continue
		}
		seen[addr] = true
		out = append(out, addr)
	}
	return out
}

// connectLoginOnly 只做登录（用于授信终端操作），不取资源也不建隧道。
func (c *Client) connectLoginOnly(ctx context.Context, password string) (*Session, error) {
	return c.newSession(ctx, password, true)
}

// Close 登出并释放本地资源。可重复调用。
func (s *Session) Close(ctx context.Context) error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.cancel()
		conn := s.active
		s.active = nil
		done := s.runDone
		streams := make([]*TCPConn, 0, len(s.tcpConnections))
		for stream := range s.tcpConnections {
			streams = append(streams, stream)
		}
		s.mu.Unlock()
		for _, stream := range streams {
			_ = stream.Close()
		}
		s.dials.Wait()

		if conn != nil {
			_ = conn.Close()
		}
		if done != nil {
			<-done
		}
		// 只在真的建立过登录会话时登出。
		if s.ctrl != nil && s.ticket != "" {
			logoutCtx, cancel := context.WithTimeout(ctx, controlTimeout)
			defer cancel()
			if err := s.ctrl.logout(logoutCtx); err != nil {
				s.closeErr = err
			}
		}
		if s.ctrl != nil {
			s.ctrl.hc.CloseIdleConnections()
		}
	})
	return s.closeErr
}

func pickPasswordMethod(methods []authMethod, domain string) (authMethod, error) {
	var fallback *authMethod
	for i := range methods {
		m := methods[i]
		if m.AuthType != "auth/psw" {
			continue
		}
		if domain != "" && m.LoginDomain == domain {
			return m, nil
		}
		if fallback == nil {
			fallback = &methods[i]
		}
	}
	if domain != "" {
		return authMethod{}, &ProtocolError{What: "配置的口令登录域不存在"}
	}
	if fallback != nil {
		return *fallback, nil
	}
	return authMethod{}, &ProtocolError{What: "服务端没有可用的口令登录方式"}
}

// randomSignKey 生成逐流鉴权用的签名密钥。
//
// 实测服务端不校验签名（密钥从不外发），但没理由因此用一个常量：它一旦被
// 校验起来，所有部署会共用同一把密钥。
func randomSignKey() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // Go 1.26 的 crypto/rand.Read 成功填满；熵源失败会终止进程。
	return b
}

func maskPhone(raw string) string {
	var digits []byte
	for i := 0; i < len(raw); i++ {
		if raw[i] >= '0' && raw[i] <= '9' {
			digits = append(digits, raw[i])
		}
	}
	if len(digits) < 4 {
		return "已登记手机号"
	}
	return "***" + string(digits[len(digits)-4:])
}

// Done 关闭表示共享登录结束；局部 L3 故障不会关闭它。
func (s *Session) Done() <-chan struct{} { return s.ctx.Done() }

func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failure != nil {
		return s.failure
	}
	return s.ctx.Err()
}

// invalidate 只发起收敛，不在调用它的读协程内等待自身。Close 负责等待和登出。
func (s *Session) invalidate(err error) {
	s.mu.Lock()
	if s.failure != nil || s.closed {
		s.mu.Unlock()
		return
	}
	s.failure = err
	s.cancel()
	conn := s.active
	streams := make([]*TCPConn, 0, len(s.tcpConnections))
	for c := range s.tcpConnections {
		streams = append(streams, c)
	}
	s.mu.Unlock()
	if conn != nil {
		conn.close(err)
	}
	for _, c := range streams {
		_ = c.Close()
	}
}

// StopL3 只释放 L3 连接；调用方先取消并等待 Run，再调用本方法。
func (s *Session) StopL3() {
	s.mu.Lock()
	conn := s.active
	s.active = nil
	s.runDone = nil
	s.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}
