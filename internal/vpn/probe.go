package vpn

import (
	"errors"
	"fmt"
	"log"
	"net"
	"time"
)

const (
	// queryIPAttempts 是 query-ip 阶段的最大尝试次数。
	queryIPAttempts = 3
	// queryIPBackoff 是两次尝试之间的等待时间。
	//
	// 实测这个重试越密集越失败：服务端对同一账号的建连有限制，频繁重试反而
	// 会让它一直处于拒绝状态（同一 TwfID 连试 5 次、每次间隔 15 秒，五次全败）。
	// 因此这里只留少量尝试、间隔拉长，真正的恢复靠用户稍后重来。
	queryIPBackoff = 30 * time.Second
)

// Stage 是探测过程中的一个步骤及其耗时。
type Stage struct {
	Name     string
	Duration time.Duration
	Err      error
}

// ProbeResult 记录一次协议探测的结果。
type ProbeResult struct {
	Server   string
	TwfID    string
	Token    string
	ClientIP string
	// NeedAuth 非 nil 表示服务端要求二次验证，且本次没有提交验证码。
	NeedAuth error
	Stages   []Stage

	// QueryConn 是 query-ip 阶段建立的连接。它必须在隧道存活期间保持打开，
	// 否则服务端会断开 i/o 流。调用方负责关闭。
	QueryConn net.Conn
	// IPRev 是客户端 IP 的字节反序，隧道首包用它标识会话。
	IPRev *[4]byte
}

// AuthPrompt 在服务端要求二次验证时被调用，返回用户输入的验证码。
// kind 是 ERR_NEXT_AUTH_SMS 或 ERR_NEXT_AUTH_TOTP。
type AuthPrompt func(kind error) (string, error)

// Probe 依次验证 Web 登录、portal token 和隧道握手，用来确认协议在当前
// 服务端和网络路径上仍然可用。
//
// code 用于二次验证：TOTP 直接提交，短信验证码也走同一个入口。
// code 为空且 prompt 非空时，向 prompt 索取验证码并在同一次登录会话里继续；
// code 为空且 prompt 为 nil 时只探测到登录阶段，把 NeedAuth 交回给调用方。
//
// twfId 非空时跳过 Web 登录，直接用已有的会话继续，省掉一次短信验证。
func (client *Client) Probe(username, password, twfId, code string, debug bool, prompt AuthPrompt) (*ProbeResult, error) {
	res := &ProbeResult{Server: client.server}

	step := func(name string, fn func() error) error {
		start := time.Now()
		err := fn()
		res.Stages = append(res.Stages, Stage{Name: name, Duration: time.Since(start), Err: err})
		return err
	}

	var loginErr error
	if twfId == "" {
		if err := step("web-login", func() error {
			var err error
			twfId, err = client.WebLogin(username, password)
			if err != nil && !errors.Is(err, ERR_NEXT_AUTH_SMS) && !errors.Is(err, ERR_NEXT_AUTH_TOTP) {
				return err
			}
			loginErr = err
			return nil
		}); err != nil {
			return res, err
		}
	} else {
		res.Stages = append(res.Stages, Stage{Name: "web-login", Duration: 0, Err: nil})
	}
	res.TwfID = twfId

	switch {
	case loginErr == nil:
	case errors.Is(loginErr, ERR_NEXT_AUTH_TOTP), errors.Is(loginErr, ERR_NEXT_AUTH_SMS):
		if code == "" {
			if prompt == nil {
				res.NeedAuth = loginErr
				return res, nil
			}
			var err error
			code, err = prompt(loginErr)
			if err != nil {
				return res, err
			}
			if code == "" {
				res.NeedAuth = loginErr
				return res, nil
			}
		}
		name := "auth-totp"
		if errors.Is(loginErr, ERR_NEXT_AUTH_SMS) {
			name = "auth-sms"
		}
		if err := step(name, func() error {
			var err error
			if errors.Is(loginErr, ERR_NEXT_AUTH_SMS) {
				twfId, err = client.AuthSms(twfId, code)
			} else {
				twfId, err = client.TOTPAuth(twfId, code)
			}
			return err
		}); err != nil {
			return res, err
		}
		res.TwfID = twfId
	default:
		return res, loginErr
	}

	var token string
	if err := step("portal-token", func() error {
		var err error
		token, err = client.PortalToken(twfId)
		return err
	}); err != nil {
		return res, err
	}
	res.Token = token

	full := (*[48]byte)([]byte(token + twfId))

	var clientIP []byte
	var queryConn net.Conn
	// 服务端对同一 TwfID 的并发建连有限制：连着建连会返回一段固定的内存数据。
	// 这里做几次退避重试，避免把服务端的限流当成协议错误。
	if err := step("query-ip", func() error {
		var lastErr error
		for attempt := 1; attempt <= queryIPAttempts; attempt++ {
			// 用具体类型接收：QueryIp 失败时返回的是 nil 的 *tls.UConn，
			// 直接赋给 net.Conn 会得到一个非 nil 的接口，Close() 会崩。
			ip, conn, err := client.QueryIp(full, debug)
			if err == nil {
				clientIP, queryConn = ip, conn
				return nil
			}
			lastErr = err
			if conn != nil {
				conn.Close()
			}
			var ctrl *ControlError
			if !errors.As(err, &ctrl) || !ctrl.Retryable() {
				return err
			}
			if attempt < queryIPAttempts {
				log.Printf("query-ip 第 %d 次被服务端拒绝，%s 后重试", attempt, queryIPBackoff)
				time.Sleep(queryIPBackoff)
			}
		}
		return lastErr
	}); err != nil {
		return res, err
	}
	// QueryIp 的连接必须保持到隧道握手完成，否则服务端会断开 i/o 流。
	res.ClientIP = net.IP(clientIP).String()
	res.QueryConn = queryConn

	ipRev := &[4]byte{clientIP[3], clientIP[2], clientIP[1], clientIP[0]}
	res.IPRev = ipRev
	if err := step("tunnel-handshake", func() error {
		return client.ProbeTunnel(full, ipRev, debug)
	}); err != nil {
		queryConn.Close()
		return res, err
	}

	return res, nil
}

// Summary 返回适合打印的一行摘要。
func (r *ProbeResult) Summary() string {
	if r.NeedAuth != nil {
		return fmt.Sprintf("需要二次验证: %v", r.NeedAuth)
	}
	if len(r.Stages) == 0 {
		return "没有执行任何步骤"
	}
	last := r.Stages[len(r.Stages)-1]
	if last.Err != nil {
		return fmt.Sprintf("在 %s 阶段失败: %v", last.Name, last.Err)
	}
	return fmt.Sprintf("全部 %d 个阶段通过，分配地址 %s", len(r.Stages), r.ClientIP)
}
