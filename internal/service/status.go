// Package service 是服务进程的主体：状态机加上隧道生命周期。
//
// 结构上是一个 actor：所有会改状态的操作都被送到单条命令通道上串行执行，
// 因此"状态"不需要用锁保护，也不会出现两个操作同时动同一份资源。
// 对外的只读查询走一份独立的快照，永远不会被正在进行的网络 I/O 挡住。
package service

import (
	"log"
	"sync"
	"time"
)

// State 是服务进程对外可见的状态。
type State string

const (
	StateIdle        State = "idle"         // 未连接
	StateLoggingIn   State = "logging_in"   // 正在登录
	StateAuthPending State = "auth_pending" // 等待用户提交验证码
	StateConnecting  State = "connecting"   // 正在建立承载
	StateUp          State = "up"           // 隧道已通
	StateError       State = "error"        // 上一次操作失败
)

// Status 是一次状态查询的完整结果。
type Status struct {
	State  State  `json:"state"`
	Detail string `json:"detail,omitempty"`
	// Retrying 表示链路已经断开、正在退避重连。
	//
	// 这时状态仍是 up（隧道对象与承载层都还在，重连成功后不需要重建），
	// 但链路是断的——只看 State 的话，status -check 会把断了的链路报成正常，
	// 巡检脚本因此永远发现不了。
	Retrying bool   `json:"retrying,omitempty"`
	ClientIP string `json:"client_ip,omitempty"` // 校园网分配的地址
	PeerIP   string `json:"peer_ip,omitempty"`   // 客户端 peer 的地址
	// Since 是进入当前状态的时间，便于判断"卡了多久"。
	Since time.Time `json:"since"`
	// Identity 是实例身份，用来区分同机上的多个实例。
	Identity Identity `json:"identity"`
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

// transitions 是状态迁移表。key 是当前状态，value 是允许进入的下一状态。
//
// error 与 idle 从任何状态都可达：失败与断开必须在任何时刻都能收敛，
// 没有恢复路径的状态机是运维事故的温床。
var transitions = map[State][]State{
	StateIdle:        {StateLoggingIn, StateError},
	StateLoggingIn:   {StateAuthPending, StateConnecting, StateIdle, StateError},
	StateAuthPending: {StateLoggingIn, StateConnecting, StateIdle, StateError},
	StateConnecting:  {StateUp, StateIdle, StateError},
	StateUp:          {StateIdle, StateError},
	StateError:       {StateIdle, StateLoggingIn, StateError},
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

// set 迁移到 next 状态。
//
// 非法迁移会写日志并照样迁移：调用点分布在错误路径上，返回错误只会被
// 丢掉（以前 8 个调用点里有 5 个写成下划线），结果是状态静默停在原地，
// 对外还是一个看起来正常的状态，比迁移错误本身更难排查。
func (s *statusStore) set(next State, detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cur := s.status.State
	if cur != next && !allowed(cur, next) {
		log.Printf("状态从 %s 迁移到 %s 不在预期内（继续迁移）", cur, next)
	}
	s.applyLocked(next, detail)
}

// setDetail 只更新说明文字。
func (s *statusStore) setDetail(detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.Detail = detail
}

// setRetrying 标记链路是否正在重连。
func (s *statusStore) setRetrying(retrying bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.Retrying = retrying
}

// setAddresses 记录隧道地址与 peer 地址。
func (s *statusStore) setAddresses(clientIP, peerIP string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.ClientIP = clientIP
	s.status.PeerIP = peerIP
}

// clearAddresses 清空地址信息。
func (s *statusStore) clearAddresses() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.ClientIP = ""
	s.status.PeerIP = ""
}

// applyLocked 写入新状态。调用方需持有写锁。
func (s *statusStore) applyLocked(next State, detail string) {
	if s.status.State != next {
		s.status.Since = time.Now()
	}
	s.status.State = next
	s.status.Detail = detail
	// 离开运行态时地址信息必须一起清掉，否则 status 会显示
	// "idle | 已断开 | peer 10.66.66.2" 这种自相矛盾的内容。
	if next == StateIdle || next == StateError {
		s.status.ClientIP = ""
		s.status.PeerIP = ""
		s.status.Retrying = false
	}
}

func allowed(cur, next State) bool {
	for _, s := range transitions[cur] {
		if s == next {
			return true
		}
	}
	return false
}
