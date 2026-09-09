package service

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"njuvpn/internal/config"
	"njuvpn/internal/dial"
	"njuvpn/internal/vpn"
	"njuvpn/internal/wireguard"
)

// ErrNotRunning 表示服务进程还没有建立隧道。
var ErrNotRunning = errors.New("隧道未运行")

// Service 持有一次隧道连接的全部资源。
type Service struct {
	cfg   *config.Config
	state *machine

	mu        sync.Mutex
	client    *vpn.Client
	relay     *wireguard.Relay
	endpoint  *vpn.TunnelEndpoint
	twfID     string
	authKind  error // 上一次登录要求的二次验证方式
	queryConn net.Conn
}

// New 构造服务对象。
func New(cfg *config.Config) *Service {
	return &Service{cfg: cfg, state: newMachine()}
}

// Status 返回当前状态。
func (s *Service) Status() Status { return s.state.Get() }

// Start 建立隧道。
//
// 若服务端要求二次验证，会切到 auth_pending 并返回 ErrAuthRequired，
// 由调用方通过 Auth 提交验证码后继续。
func (s *Service) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cur := s.state.Get().State
	// 等待验证码时再次 start，意味着用户没收到码、想重新要一条。
	// 旧 TwfID 上重复请求会被服务端拒绝（unexpected user service），
	// 所以丢弃旧会话，重新走一遍登录拿新的。
	if cur == StateAuthPending {
		s.release()
		if err := s.state.Transition(StateIdle, "重新登录"); err != nil {
			return err
		}
		cur = StateIdle
	}

	if cur != StateIdle && cur != StateError {
		return fmt.Errorf("当前状态是 %s，无法开始新的连接", cur)
	}

	if err := s.state.Transition(StateLoggingIn, "正在登录"); err != nil {
		return err
	}

	dialFn, err := dial.New(s.cfg.Proxy)
	if err != nil {
		s.fail(err)
		return err
	}
	s.client = vpn.NewClient(s.cfg.ServerAddr(), dialFn)

	// TOTP 密钥存在时无人值守完成验证，省掉人工介入。
	code := ""
	if s.cfg.TOTPSecret != "" {
		code, err = vpn.GenerateTOTP(s.cfg.TOTPSecret)
		if err != nil {
			s.fail(err)
			return err
		}
	}

	res, err := s.client.Probe(s.cfg.Username, s.cfg.Password, "", code, false, nil)
	if err != nil {
		s.fail(err)
		return err
	}
	s.twfID = res.TwfID
	s.authKind = res.NeedAuth

	if res.NeedAuth != nil {
		return s.awaitAuth()
	}

	return s.finishConnect(res)
}

// Auth 提交二次验证码。仅在 auth_pending 状态下有效。
func (s *Service) Auth(code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state.Get().State != StateAuthPending {
		return fmt.Errorf("当前状态是 %s，不需要验证码", s.state.Get().State)
	}
	if code == "" {
		return errors.New("验证码为空")
	}

	res, err := s.client.Probe(s.cfg.Username, s.cfg.Password, s.twfID, code, false, nil)
	if err != nil {
		// 验证码本身错了不该把整个会话打回 idle：TwfID 还有效，
		// 用户可以再输一次。这里保持 auth_pending 并带上原因。
		if isAuthCodeError(err) {
			s.state.SetDetail(err.Error())
			return err
		}
		s.fail(err)
		return err
	}
	if res.NeedAuth != nil {
		return s.awaitAuth()
	}

	return s.finishConnect(res)
}

// Stop 断开隧道并释放资源。
func (s *Service) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state.Get().State == StateIdle {
		return ErrNotRunning
	}
	// release 内部会先登出再释放本地资源。
	s.release()
	return s.state.Transition(StateIdle, "已断开")
}

// release 关闭所有底层资源。调用方需持有 s.mu。
func (s *Service) release() {
	s.logoutLocked()
	s.closeResources()
}

// logoutLocked 通知服务端注销当前会话。调用方需持有 s.mu。
//
// 不登出就丢弃 TWFID，会在服务端留下一个占用名额的会话；
// 反复失败重试就会把账号的隧道名额耗尽。
func (s *Service) logoutLocked() {
	if s.client == nil || s.twfID == "" {
		return
	}
	if err := s.client.Logout(s.twfID); err != nil {
		log.Printf("服务端登出未成功: %v", err)
		return
	}
	log.Printf("已通知服务端注销会话")
}

// closeResources 释放本地资源。调用方需持有 s.mu。
func (s *Service) closeResources() {
	if s.relay != nil {
		s.relay.Close()
		s.relay = nil
	}
	if s.queryConn != nil {
		s.queryConn.Close()
		s.queryConn = nil
	}
	s.endpoint = nil
	s.client = nil
	s.twfID = ""
	s.authKind = nil
}

// awaitAuth 切到等待验证码状态。调用方需持有 s.mu。
func (s *Service) awaitAuth() error {
	var detail string
	switch {
	case errors.Is(s.authKind, vpn.ERR_NEXT_AUTH_TOTP):
		detail = "需要 TOTP 验证码，请执行 njuvpn auth <code>"
	case errors.Is(s.authKind, vpn.ErrSMSSent):
		detail = "验证码已发送到手机，请执行 njuvpn auth <code>"
	case errors.Is(s.authKind, vpn.ErrSMSTooMany):
		detail = "短信发送过于频繁，请稍后再试"
	case s.authKind != nil:
		detail = vpn.UserMessage(s.authKind) + "，请执行 njuvpn auth <code>"
	default:
		detail = "需要短信验证码，请执行 njuvpn auth <code>"
	}
	if err := s.state.Transition(StateAuthPending, detail); err != nil {
		return err
	}
	return fmt.Errorf("%s: %w", detail, ErrAuthRequired)
}

// finishConnect 用一次成功的探测结果建立 WireGuard 承载。
func (s *Service) finishConnect(res *vpn.ProbeResult) error {
	if err := s.state.Transition(StateConnecting, "正在建立 WireGuard 承载"); err != nil {
		return err
	}

	s.endpoint = &vpn.TunnelEndpoint{}
	s.relay = wireguard.NewRelay(s.cfg.MTU, s.endpoint)
	s.queryConn = res.QueryConn

	token := (*[48]byte)([]byte(res.Token + res.TwfID))
	ipRev := res.IPRev

	// 隧道启动放在后台：StartProtocol 会一直阻塞在收发循环里。
	client := s.client
	go client.StartProtocol(s.endpoint, token, ipRev, false)

	s.state.SetAddresses(res.ClientIP, s.cfg.WireGuard.PeerAddress)
	if err := s.state.Transition(StateUp, "隧道已建立"); err != nil {
		return err
	}

	log.Printf("隧道已建立：校园网地址 %s，peer 地址 %s", res.ClientIP, s.cfg.WireGuard.PeerAddress)
	return nil
}

// fail 记录失败状态。调用方需持有 s.mu。
func (s *Service) fail(err error) {
	s.release()
	if cur := s.state.Get().State; cur != StateIdle {
		_ = s.state.Transition(StateError, err.Error())
	}
}

// ErrAuthRequired 表示需要提交验证码才能继续。
var ErrAuthRequired = errors.New("需要二次验证")

// isAuthCodeError 判断错误是否只是验证码不对，而不是会话失效。
func isAuthCodeError(err error) bool {
	return errors.Is(err, vpn.ErrSMSWrongCode) ||
		errors.Is(err, vpn.ErrSMSExpired) ||
		errors.Is(err, vpn.ErrSMSTooMany)
}

// WaitReady 等待隧道进入 up 状态，用于测试和启动检查。
func (s *Service) WaitReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.state.Get().State == StateUp {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("等待隧道就绪超时（当前状态 %s）", s.state.Get().State)
}
