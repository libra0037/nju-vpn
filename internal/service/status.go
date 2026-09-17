// Package service 是服务进程的主体：状态机加上隧道生命周期。
//
// 结构上是一个 actor：所有会改状态的操作都被送到单条命令通道上串行执行，
// 因此状态不需要用锁保护，也不会出现两个操作同时动同一份资源。对外的
// 只读查询走一份独立的快照，永远不会被正在进行的网络 I/O 挡住。
//
// 三条贯穿全包的规则：
//
//   - 不在持锁时做网络 I/O；
//   - 半完成的登录必须留下来（拿着它才登得出去），不能丢掉，否则服务端
//     那条"同一账号只允许一个客户端"的名额要等它自己超时才释放；
//   - 隧道协程的每一条汇报都带代次，过期汇报不许改状态。
package service

import (
	"sync"
	"time"
)

// State 是服务进程对外可见的状态。
type State string

const (
	StateIdle        State = "idle"         // 未连接
	StateLoggingIn   State = "logging_in"   // 正在登录 / 建隧道
	StateAuthPending State = "auth_pending" // 等待用户提交验证码
	StateUp          State = "up"           // 隧道已通
	StateError       State = "error"        // 上一次操作失败
)

// Status 是一次状态查询的完整结果。
type Status struct {
	State  State  `json:"state"`
	Detail string `json:"detail,omitempty"`
	// Retrying 表示链路已经断开、正在退避重连。
	//
	// 这时状态仍是 up（登录会话、隧道对象与承载层都还在，重连成功后不必
	// 重建它们），但链路是断的——只看 State 的话，巡检脚本会把断了的链路
	// 报成正常，因此它必须能单独看见。
	Retrying bool `json:"retrying,omitempty"`
	// ClientIP / PeerIP 不在这份快照里：会话挂着时由 Service.Status 现取
	// （端点上的当前地址加配置里的 peer 地址），会话摘掉后为空。
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
// 这里不做"迁移是否合法"的判定：那张表曾经存在，但把每一条真实路径都走
// 过一遍之后发现它拦的迁移一次都没发生过（隧道协程的汇报都带代次，过期
// 汇报在调用点就被丢掉了），留着只会给读者一个"能报警"的错觉。状态是否
// 合理由各调用点自己的前置条件保证（例如 tunnelDown 只看当前代次）。
func (s *statusStore) set(next State, detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applyLocked(next, detail)
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
	s.status.Retrying = retrying
}

// applyLocked 写入新状态。调用方需持有写锁。
func (s *statusStore) applyLocked(next State, detail string) {
	if s.status.State != next {
		s.status.Since = time.Now()
	}
	s.status.State = next
	s.status.Detail = detail
	// 离开运行态时不再显示“正在重连”。地址不在这里清：它由 Service.Status
	// 现取，会话摘掉后自然为空（见那里的注释）。
	if next == StateIdle || next == StateError {
		s.status.Retrying = false
	}
}
