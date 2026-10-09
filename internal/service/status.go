// Package service 管理共享校园会话及 WireGuard、SOCKS5 的生命周期。
//
// 结构上是一个 actor：所有会改状态的操作都被送到单条命令通道上串行执行，
// 因此状态不需要用锁保护，也不会出现两个操作同时动同一份资源。对外的
// 只读查询走一份独立的快照，永远不会被正在进行的网络 I/O 挡住。
//
// 三条贯穿全包的规则：
//
//   - 不在持锁时做网络 I/O；
//   - 半完成的登录必须留下来（拿着它才登得出去），不能丢掉，否则服务端
//     那条"同一账号只允许一条隧道会话"的名额要等它自己超时才释放；
//   - 异步汇报携带任务身份，局部 L3 用代次，共享会话与 SOCKS 用对象身份。
package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/libra0037/nju-vpn/internal/dial"
	"github.com/libra0037/nju-vpn/internal/socks5"
	"github.com/libra0037/nju-vpn/internal/wireguard"
	"github.com/libra0037/nju-vpn/internal/ztna"
)

// State 是服务进程对外可见的状态。
type State string

const (
	StateIdle        State = "idle"         // 未连接
	StateLoggingIn   State = "logging_in"   // 正在登录 / 建隧道
	StateAuthPending State = "auth_pending" // 等待用户提交验证码
	StateUp          State = "up"           // 校园会话已登录；各端点就绪另行派生
	StateError       State = "error"        // 上一次操作失败
)

// Status 是一次状态查询的完整结果。
type Status struct {
	State        State                   `json:"state"`
	Detail       string                  `json:"detail,omitempty"`
	Failure      string                  `json:"failure,omitempty"` // 有限错误类别，不依赖错误文本。
	WireGuard    WireGuardStatus         `json:"wireguard"`
	SOCKS5       SOCKS5Status            `json:"socks5"`
	Ready        bool                    `json:"ready"`
	SessionReady bool                    `json:"session_ready"`
	Tunnel       *ztna.TunnelDiagnostics `json:"tunnel,omitempty"`
	// Retrying 表示链路已经断开、正在退避重连。
	//
	// 这时状态仍是 up（登录会话、隧道对象与承载层都还在，重连成功后不必
	// 重建它们），但链路是断的——只看 State 的话，巡检脚本会把断了的链路
	// 报成正常，因此它必须能单独看见。
	Retrying bool `json:"retrying,omitempty"`
	// ClientIP / PeerIP 不在这份快照里：会话挂着时由 Service.Status 现取
	// （端点上的当前地址加配置里的 peer 地址），会话摘掉后为空。
	ClientIP string `json:"client_ip,omitempty"` // 校园网分配的地址
	PeerIP   string `json:"peer_ip,omitempty"`   // 对端 peer 的地址
	// Since 是进入当前状态的时间，便于判断"卡了多久"。
	Since time.Time `json:"since"`
	// Identity 是实例身份，用来区分同机上的多个实例。
	Identity Identity `json:"identity"`
}

// Enabled 是当前任务的启用意图，局部 stop 可关闭它；全局 start 按配置重置。
type WireGuardStatus struct {
	wireguard.Diagnostics
	Enabled   bool   `json:"enabled"`
	Listening bool   `json:"listening"`
	Failure   string `json:"failure,omitempty"`
}
type SOCKS5Status struct {
	socks5.Diagnostics
	Enabled bool   `json:"enabled"`
	Failure string `json:"failure,omitempty"`
}

func failureKind(err error) string {
	var rejected *ztna.ErrCodeRejected
	var gone *ztna.ErrSessionGone
	var protocol *ztna.ProtocolError
	var network *dial.Error
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ztna.ErrControlTLS):
		return "control_tls"
	case errors.Is(err, ztna.ErrNodeUntrusted):
		return "node_untrusted"
	case errors.Is(err, ztna.ErrNodeTLS):
		return "node_tls"
	case errors.As(err, &rejected):
		return "auth_rejected"
	case errors.As(err, &gone):
		return "session_expired"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.As(err, &protocol):
		return "protocol"
	case errors.As(err, &network):
		return "network"
	default:
		return "internal"
	}
}

// Identity 描述"在跟哪个实例说话"。
//
// 同机多实例同时连同一台学校服务器时，日志与状态几乎逐字相同，排查时
// 容易张冠李戴；这四个字段足以对上号，且不含任何凭据。
type Identity struct {
	PID        int    `json:"pid"`
	ConfigPath string `json:"config,omitempty"`
	Endpoint   string `json:"endpoint,omitempty"`
	Username   string `json:"username,omitempty"`
}

// statusStore 保存对外可见的状态快照。
//
// 只有 actor 协程写它，任何协程都可以读。
type statusStore struct {
	mu     sync.RWMutex
	status Status
}

func newStatusStore(id Identity) *statusStore {
	return &statusStore{status: Status{State: StateIdle, Since: time.Now(), Identity: id}}
}

// Get 返回当前状态的快照。
func (s *statusStore) Get() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

// set 拒绝非法迁移；外层命令边界负责收尾并输出不含凭据的内部错误。
func (s *statusStore) set(next State, detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validTransition(s.status.State, next) {
		panic(fmt.Sprintf("非法服务状态迁移：%s → %s", s.status.State, next))
	}
	s.applyLocked(next, detail)
}

func (s *statusStore) setError(detail string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validTransition(s.status.State, StateError) {
		panic("当前服务状态不能进入错误状态")
	}
	s.applyLocked(StateError, detail)
	s.status.Failure = failureKind(err)
}

func (s *statusStore) setLinkFailure(detail string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status.State != StateUp {
		panic("仅运行中的隧道可以进入重连状态")
	}
	s.status.Retrying = true
	s.status.Detail = detail
	s.status.Failure = failureKind(err)
}

func validTransition(from, to State) bool {
	switch from {
	case StateIdle:
		return to == StateIdle || to == StateLoggingIn || to == StateError
	case StateLoggingIn:
		return to == StateLoggingIn || to == StateAuthPending || to == StateUp || to == StateIdle || to == StateError
	case StateAuthPending:
		return to == StateAuthPending || to == StateUp || to == StateIdle || to == StateError
	case StateUp:
		return to == StateUp || to == StateIdle || to == StateError
	case StateError:
		return to == StateError || to == StateIdle || to == StateLoggingIn
	default:
		return false
	}
}

// setDetail 只更新说明文字，状态不变。
func (s *statusStore) setDetail(detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.Detail = detail
}

// setRetrying 标记链路是否正在重连。
func (s *statusStore) setRetrying(retrying bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if retrying && s.status.State != StateUp {
		panic("仅运行中的隧道可以进入重连状态")
	}
	s.status.Retrying = retrying
	if !retrying {
		s.status.Failure = ""
	}
}

// applyLocked 写入新状态。调用方需持有写锁。
func (s *statusStore) applyLocked(next State, detail string) {
	if s.status.State != next {
		s.status.Since = time.Now()
	}
	s.status.State = next
	s.status.Detail = detail
	s.status.Failure = ""
	// 离开运行态时不再显示“正在重连”。地址不在这里清：它由 Service.Status
	// 现取，会话摘掉后自然为空（见那里的注释）。
	if next == StateIdle || next == StateError {
		s.status.Retrying = false
	}
}

// 端点意图与失败仅由 actor 更新；连接/监听诊断在 Status 时从实际对象派生。
func (s *statusStore) endpoint(wireguard bool, enabled bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if wireguard {
		s.status.WireGuard.Enabled = enabled
		s.status.WireGuard.Failure = failureKind(err)
	} else {
		s.status.SOCKS5.Enabled = enabled
		s.status.SOCKS5.Failure = failureKind(err)
	}
}
