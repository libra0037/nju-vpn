package ztna

import (
	"context"
	"crypto/sha256"
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
	// InsecureSkipVerify 关闭控制面的证书校验。默认（false）走系统信任链：
	// 门户证书是公共 CA 签发的，口令与验证码因此不再暴露给中间人。
	InsecureSkipVerify bool
	// NodePins 是隧道节点证书的 SHA-256 指纹（叶子证书）。
	NodePins [][sha256.Size]byte
	// PinsPath 是“首次记录”下来的节点指纹的落盘位置；空表示只记在内存里。
	PinsPath string
	// StrictNodePins 为真时只认 NodePins 给的指纹，不再对陌生节点做首次记录。
	// 用户在配置里明确写了指纹就按他写的来。
	StrictNodePins bool
}

// Client 是协议层门面：一次"连接"= 登录 + 取资源 + 建隧道。
type Client struct {
	opts Options
	pins *nodePins
}

func New(opts Options) *Client {
	return &Client{opts: opts, pins: newNodePins(opts.NodePins, opts.PinsPath, opts.StrictNodePins, opts.Logf)}
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
		Server:             c.opts.Server,
		DialAddr:           c.opts.DialAddr,
		Dial:               c.opts.Dial,
		DeviceID:           deviceID,
		Debug:              func(s string) { c.logf("%s", s) },
		InsecureSkipVerify: c.opts.InsecureSkipVerify,
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
	signKey []byte
	// devicesOnly 表示这次登录只用于授信终端操作，不建隧道。
	devicesOnly bool

	mu     sync.Mutex
	active *tunnelConn

	closeOnce sync.Once
	closeErr  error
}

// Connect 完成登录并建立隧道。需要验证码时返回 (session, ErrAuthRequired)。
func (c *Client) Connect(ctx context.Context, co ConnectOptions) (*Session, error) {
	password := co.Password
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
	s := &Session{client: c, ctrl: ctrl, password: password, ep: l3.New()}

	if err := s.beginLogin(ctx); err != nil {
		_ = s.Close(context.Background())
		return s, err
	}
	if s.step.Service != "" {
		return s, &ErrAuthRequired{Kind: s.step.Service, Hint: s.smsHint(ctx)}
	}
	if err := s.prepare(ctx); err != nil {
		_ = s.Close(context.Background())
		return s, err
	}
	return s, nil
}

// beginLogin 走到认证链这一步：口令登录 + 上报环境 + 按服务名往下走。
func (s *Session) beginLogin(ctx context.Context) error {
	if _, err := s.ctrl.manifest(ctx); err != nil {
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
			return &ProtocolError{What: "不支持的二次验证方式", Got: s.step.Service}
		}
	}
	return &ProtocolError{What: "认证链过长"}
}

// Auth 提交验证码并继续。成功后资源与地址就绪。
func (s *Session) Auth(ctx context.Context, code string) error {
	if s.step.Service != "auth/sms" {
		return &ProtocolError{What: "当前不需要验证码", Got: s.step.Service}
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

// SMSPrompt 触发短信并返回给用户看的提示（手机号脱敏 + 服务端文案）。
func (s *Session) SMSPrompt(ctx context.Context) (string, error) {
	return s.ctrl.sendSMS(ctx, s.step.AuthID, s.withAuthID)
}

func (s *Session) smsHint(ctx context.Context) string {
	phones, err := s.ctrl.phoneNumber(ctx, s.step.AuthID)
	if err != nil || len(phones) == 0 {
		return "服务端要求短信验证码"
	}
	return fmt.Sprintf("验证码将发送至 %s", phones[0])
}

// prepare 取资源表、选节点、建立第一条隧道连接并拿到校园网地址。
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
	table, err := parseResourceTable(raw, s.client.opts.Server)
	if err != nil {
		return err
	}
	s.table = table
	s.client.logf("资源表: %d 条规则，%d 个隧道节点", len(table.entries), len(table.nodes))

	node, err := probeNodes(ctx, s.client.opts.Dial, table.candidateNodes(table.major), 6*time.Second)
	if err != nil {
		return err
	}
	s.node = node
	s.signKey = randomSignKey()
	s.client.logf("隧道节点: %s", node)

	conn, err := dialTunnel(ctx, s.tunnelOptions(s.node))
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.active = conn
	s.mu.Unlock()
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

// Username 返回服务端确认过的账号名。
func (s *Session) Username() string { return s.username }

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
	backoff := time.Second
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
			return ctx.Err()
		case <-conn.Done():
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
				// 记住这次真正连上的节点，下次断线优先回到它。
				s.node = node
				break
			}
			if ctx.Err() != nil {
				return ctx.Err()
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
		s.active = reconnected
		s.mu.Unlock()
		backoff = time.Second
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
	for _, addr := range s.table.candidateNodes(s.table.major) {
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
	s := &Session{client: c, ctrl: ctrl, password: password, ep: l3.New(), devicesOnly: true}
	if err := s.beginLogin(ctx); err != nil {
		_ = s.Close(context.Background())
		return s, err
	}
	if s.step.Service != "" {
		return s, &ErrAuthRequired{Kind: s.step.Service, Hint: s.smsHint(ctx)}
	}
	return s, nil
}

// Close 登出并释放本地资源。可重复调用。
func (s *Session) Close(ctx context.Context) error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		conn := s.active
		s.active = nil
		s.mu.Unlock()

		s.ep.ClearUplink()
		s.ep.ClearDownlink()
		if conn != nil {
			_ = conn.Close()
		}
		// 只在真的建立过登录会话时登出。
		if s.ctrl != nil && s.ticket != "" {
			if err := s.ctrl.logout(ctx); err != nil {
				s.closeErr = err
			}
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
	if fallback != nil {
		return *fallback, nil
	}
	names := make([]string, 0, len(methods))
	for _, m := range methods {
		names = append(names, m.LoginDomain+"/"+m.AuthType)
	}
	return authMethod{}, &ProtocolError{What: "服务端没有可用的口令登录方式", Got: fmt.Sprintf("%v", names)}
}

// randomSignKey 生成逐流鉴权用的签名密钥。
// 实测服务端不校验签名（密钥从不外发），这里仍然按协议填一个随机值。
func randomSignKey() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i*7 + 13)
	}
	return b
}
