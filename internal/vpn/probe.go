package vpn

import (
	"fmt"
	"net"
	"time"
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
			if err != nil && err != ERR_NEXT_AUTH_SMS && err != ERR_NEXT_AUTH_TOTP {
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

	switch loginErr {
	case nil:
	case ERR_NEXT_AUTH_TOTP, ERR_NEXT_AUTH_SMS:
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
		if loginErr == ERR_NEXT_AUTH_SMS {
			name = "auth-sms"
		}
		if err := step(name, func() error {
			var err error
			if loginErr == ERR_NEXT_AUTH_SMS {
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
	if err := step("query-ip", func() error {
		var err error
		clientIP, queryConn, err = client.QueryIp(full, debug)
		return err
	}); err != nil {
		return res, err
	}
	// QueryIp 的连接必须保持到隧道握手完成，否则服务端会断开 i/o 流。
	defer queryConn.Close()
	res.ClientIP = net.IP(clientIP).String()

	ipRev := &[4]byte{clientIP[3], clientIP[2], clientIP[1], clientIP[0]}
	if err := step("tunnel-handshake", func() error {
		return client.ProbeTunnel(full, ipRev, debug)
	}); err != nil {
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
