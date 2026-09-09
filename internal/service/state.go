// Package service 是服务进程的主体：状态机加上隧道生命周期管理。
package service

import (
	"fmt"
	"sync"
)

// State 是服务进程对外可见的状态。
type State string

const (
	StateIdle        State = "idle"         // 未连接
	StateLoggingIn   State = "logging_in"   // 正在登录
	StateAuthPending State = "auth_pending" // 等待用户提交验证码
	StateConnecting  State = "connecting"   // 正在建立隧道
	StateUp          State = "up"           // 隧道已通
	StateError       State = "error"        // 上一次操作失败
)

// Status 是一次状态查询的完整结果。
type Status struct {
	State    State  `json:"state"`
	Detail   string `json:"detail,omitempty"`
	ClientIP string `json:"client_ip,omitempty"` // 校园网分配的地址
	PeerIP   string `json:"peer_ip,omitempty"`   // 客户端 peer 的地址
}

// 状态迁移表。key 是当前状态，value 是允许进入的下一状态。
var transitions = map[State][]State{
	StateIdle:        {StateLoggingIn},
	StateLoggingIn:   {StateAuthPending, StateConnecting, StateIdle, StateError},
	StateAuthPending: {StateConnecting, StateIdle, StateError},
	StateConnecting:  {StateUp, StateIdle, StateError},
	StateUp:          {StateIdle, StateError},
	StateError:       {StateIdle, StateLoggingIn},
}

// machine 是状态机本体。所有状态变更都要经过它。
type machine struct {
	mu     sync.RWMutex
	status Status
}

func newMachine() *machine {
	return &machine{status: Status{State: StateIdle}}
}

// Get 返回当前状态的快照。
func (m *machine) Get() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

// Transition 把状态切到 next，不允许的迁移会返回错误。
func (m *machine) Transition(next State, detail string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cur := m.status.State
	if cur == next {
		m.status.Detail = detail
		return nil
	}

	allowed := false
	for _, s := range transitions[cur] {
		if s == next {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("状态不允许从 %s 迁移到 %s", cur, next)
	}

	m.status.State = next
	m.status.Detail = detail
	if next == StateIdle {
		m.status.ClientIP = ""
	}
	return nil
}

// SetAddresses 记录隧道地址和 peer 地址。
func (m *machine) SetAddresses(clientIP, peerIP string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status.ClientIP = clientIP
	m.status.PeerIP = peerIP
}

// SetDetail 只更新说明文字，不改状态。
func (m *machine) SetDetail(detail string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status.Detail = detail
}
