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

// Probe 依次验证 Web 登录、portal token 和隧道握手，用来确认协议在当前
// 服务端和网络路径上仍然可用。
//
// totpCode 非空时用于 TOTP 二次验证；短信验证需要交互，Probe 只报告
// NeedAuth=ERR_NEXT_AUTH_SMS 后返回。
func (client *Client) Probe(username, password, totpCode string, debug bool) (*ProbeResult, error) {
	res := &ProbeResult{Server: client.server}

	step := func(name string, fn func() error) error {
		start := time.Now()
		err := fn()
		res.Stages = append(res.Stages, Stage{Name: name, Duration: time.Since(start), Err: err})
		return err
	}

	var twfId string
	var loginErr error
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
	res.TwfID = twfId

	switch loginErr {
	case nil:
	case ERR_NEXT_AUTH_TOTP:
		if totpCode == "" {
			res.NeedAuth = loginErr
			return res, nil
		}
		if err := step("auth-totp", func() error {
			var err error
			twfId, err = client.TOTPAuth(twfId, totpCode)
			return err
		}); err != nil {
			return res, err
		}
		res.TwfID = twfId
	case ERR_NEXT_AUTH_SMS:
		res.NeedAuth = loginErr
		return res, nil
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
		clientIP, queryConn, err = client.QueryIp(full)
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
