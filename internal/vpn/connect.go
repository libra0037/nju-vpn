package vpn

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// Stage 是连接过程中的一个步骤及其耗时。
type Stage struct {
	Name     string
	Duration time.Duration
	Err      error
}

// Trace 记录连接过程中的各个阶段，供探测命令展示。
type Trace struct {
	mu     sync.Mutex
	stages []Stage
}

// add 追加一个阶段记录。
func (t *Trace) add(name string, d time.Duration, err error) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.stages = append(t.stages, Stage{Name: name, Duration: d, Err: err})
	t.mu.Unlock()
}

// Step 执行一个阶段并记录耗时。
func (t *Trace) Step(name string, fn func() error) error {
	start := time.Now()
	err := fn()
	t.add(name, time.Since(start), err)
	return err
}

// Stages 返回阶段快照。
func (t *Trace) Stages() []Stage {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Stage, len(t.stages))
	copy(out, t.stages)
	return out
}

// Summary 返回适合打印的一行摘要。
func (t *Trace) Summary() string {
	stages := t.Stages()
	if len(stages) == 0 {
		return "没有执行任何步骤"
	}
	last := stages[len(stages)-1]
	if last.Err != nil {
		return fmt.Sprintf("在 %s 阶段失败: %v", last.Name, last.Err)
	}
	return fmt.Sprintf("全部 %d 个阶段通过", len(stages))
}

// ConnectOptions 描述一次连接。
type ConnectOptions struct {
	Username string
	Password string

	// TwfID 非空时复用已有会话，跳过 Web 登录。
	TwfID string
	// Code 是用户提交的验证码（短信或 TOTP）。
	Code string
	// AuthKind 在复用会话时指明验证码类型（ErrAuthSMS 或 ErrAuthTOTP）。
	// 为空时按短信处理。
	AuthKind error
	// TOTPSecret 非空且未提供 Code 时自动生成 TOTP 验证码。
	TOTPSecret string

	// Debug 打开后会打印握手报文（等价于凭据，只在人工排查时开）。
	Debug bool
	// Trace 记录各阶段，可为 nil。
	Trace *Trace

	// QueryIPAttempts / QueryIPBackoff 控制 query-ip 的退避重试。
	// 留空则用默认值。服务端对建连有限制，重试越密集越容易被拒。
	QueryIPAttempts int
	QueryIPBackoff  time.Duration
}

const (
	defaultQueryIPAttempts = 3
	defaultQueryIPBackoff  = 30 * time.Second
)

// Connect 完成一次登录并建立到服务端的隧道会话。
//
// 返回的 Session 在**部分失败时也可能非 nil**：只要已经拿到 TwfID，
// 调用方就必须调用 Close 让服务端释放会话名额，否则下一次登录可能被拒。
//
// 需要二次验证时返回 *AuthRequiredError（内含 TwfID 与验证方式），
// 调用方拿到验证码后带 TwfID + Code 再调一次 Connect 继续。
func (c *Client) Connect(ctx context.Context, opt ConnectOptions) (*Session, error) {
	if opt.Trace == nil {
		opt.Trace = &Trace{}
	}
	sess := &Session{
		client: c,
		ep:     NewEndpoint(),
		debug:  opt.Debug,
		trace:  opt.Trace,
	}

	twfID := opt.TwfID
	// 会话标识从这一刻起就归 Session 所有：任何一条失败路径上，
	// 调用方都必须能用它把服务端的会话登出。
	sess.twfID = twfID
	code := opt.Code
	if code == "" && opt.TOTPSecret != "" {
		generated, err := GenerateTOTP(opt.TOTPSecret)
		if err != nil {
			return sess, err
		}
		log.Printf("已用配置里的密钥生成 TOTP 验证码")
		code = generated
	}

	kind := opt.AuthKind
	needAuth := false

	if twfID == "" {
		start := time.Now()
		newTwfID, err := c.webLogin(ctx, opt.Username, opt.Password)
		authErr, isAuthErr := AsAuthRequired(err)
		// 会话标识先记到 Session 上：即使接下来就返回错误（例如短信接口
		// 出错），调用方也得能用它把服务端会话登出——同一账号只允许一条
		// 会话，登不掉的会一直占着名额。
		if newTwfID != "" {
			twfID = newTwfID
			sess.twfID = twfID
		}
		if err != nil && !isAuthErr {
			opt.Trace.add("web-login", time.Since(start), err)
			return sess, err
		}
		// 登录本身成功，只是停在二次验证上。
		opt.Trace.add("web-login", time.Since(start), nil)
		if isAuthErr {
			kind = authErr.Kind
			needAuth = true
			if code == "" {
				return sess, err
			}
		}
	} else {
		opt.Trace.add("web-login", 0, nil)
		if code != "" {
			needAuth = true
		}
	}

	if needAuth && code != "" {
		if kind == nil {
			kind = ErrAuthSMS
		}
		step := "auth-sms"
		if errors.Is(kind, ErrAuthTOTP) {
			step = "auth-totp"
		}
		err := opt.Trace.Step(step, func() error {
			newTwfID, err := c.submitCode(ctx, twfID, kind, code)
			if err != nil {
				return err
			}
			twfID = newTwfID
			return nil
		})
		if err != nil {
			return sess, err
		}
		sess.twfID = twfID
	}

	var token string
	if err := opt.Trace.Step("portal-token", func() error {
		var err error
		token, err = c.portalToken(ctx, twfID)
		return err
	}); err != nil {
		return sess, err
	}

	streamTok, err := streamToken("portal-token", token, twfID)
	if err != nil {
		return sess, err
	}
	sess.token = streamTok

	ip, queryConn, err := c.acquireIP(ctx, opt, streamTok)
	if err != nil {
		return sess, err
	}
	sess.ip = ip
	sess.ipRev = [4]byte{ip[15], ip[14], ip[13], ip[12]}
	sess.mu.Lock()
	sess.queryConn = queryConn
	sess.mu.Unlock()

	return sess, nil
}

// acquireIP 是 query-ip 阶段，带退避重试。
func (c *Client) acquireIP(ctx context.Context, opt ConnectOptions, token [streamTokenLen]byte) (net.IP, net.Conn, error) {
	attempts := opt.QueryIPAttempts
	if attempts <= 0 {
		attempts = defaultQueryIPAttempts
	}
	backoff := opt.QueryIPBackoff
	if backoff <= 0 {
		backoff = defaultQueryIPBackoff
	}

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		start := time.Now()
		ip, conn, err := c.queryIP(ctx, token, opt.Debug)
		if err == nil {
			opt.Trace.add("query-ip", time.Since(start), nil)
			return ip, conn, nil
		}
		lastErr = err
		opt.Trace.add("query-ip", time.Since(start), err)
		if !retryable(err) {
			return nil, nil, err
		}
		if attempt < attempts {
			log.Printf("query-ip 第 %d 次被拒绝: %v，%s 后重试", attempt, err, backoff)
			if err := sleepCtx(ctx, backoff); err != nil {
				return nil, nil, err
			}
		}
	}
	return nil, nil, lastErr
}

// submitCode 提交验证码，返回更新后的 TwfID。
func (c *Client) submitCode(ctx context.Context, twfID string, kind error, code string) (string, error) {
	if errors.Is(kind, ErrAuthTOTP) {
		return c.authTOTP(ctx, twfID, code)
	}
	return c.authSMS(ctx, twfID, code)
}
