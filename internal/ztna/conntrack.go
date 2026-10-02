package ztna

import (
	"errors"
	"sync"
	"time"
)

type flowState uint8

const (
	flowPending flowState = iota
	flowReady
	flowFailed
)
const (
	flowIdleTTL        = 2 * time.Minute
	flowAuthTimeout    = 8 * time.Second
	flowAuthRetryDelay = 10 * time.Second
	maxPendingPerFlow  = 64
	maxPendingPackets  = 2048
	maxPendingBytes    = 2 << 20
	maxFlows           = 8192
	maxFragments       = 1024
	// 条件支持的接收窗口：从首片算起，5 秒内仍缺末片即放弃；这是资源
	// 上限策略，不是完整 IP 重组超时。已完成关联立即删除，尾片不续期。
	fragmentTTL = 5 * time.Second
)

var (
	ErrFlowRejected      = errors.New("该流鉴权失败")
	ErrPendingFull       = errors.New("待鉴权缓存已满")
	ErrFlowTableFull     = errors.New("流表已满")
	ErrFragmentMissing   = errors.New("分片没有有效首片")
	ErrFragmentOrder     = errors.New("分片未按顺序连续到达")
	ErrFragmentFull      = errors.New("未完成分片关联已满")
	ErrResourceUnmatched = errors.New("目标不在资源表内")
	ErrPacketTooLarge    = errors.New("IP 包超过隧道 MTU")
)

type flow struct {
	key      flowKey
	appID    string
	authID   uint64
	token    string
	state    flowState
	pending  [][]byte
	authSent time.Time
	// 非零表示唯一重试预算已用，并给出可再次发送的时刻；发送后不清零。
	authRetryAt          time.Time
	createdAt, updatedAt time.Time
}
type authFlow struct {
	key    flowKey
	appID  string
	authID uint64
}
type fragmentState struct {
	flow       *flow
	expiresAt  time.Time
	nextOffset uint32
}

// 一个锁负责判定、缓存与状态迁移；不把可变 flow 交给锁外的调用者。
type flowTable struct {
	mu                           sync.Mutex
	flows                        map[flowKey]*flow
	auth                         map[uint64]*flow
	fragments                    map[fragmentKey]fragmentState
	next                         uint64
	pendingPackets, pendingBytes int
	now                          func() time.Time
	closed                       bool
}

func newFlowTable() *flowTable { return newFlowTableWithClock(time.Now) }
func newFlowTableWithClock(now func() time.Time) *flowTable {
	return &flowTable{flows: make(map[flowKey]*flow), auth: make(map[uint64]*flow), fragments: make(map[fragmentKey]fragmentState), now: now}
}

// queuePacket 返回令牌或已缓存标志。整个接收决策是一次原子操作，
// 因此鉴权成功不能插在“看到 pending”与“把包缓存”之间。
func (t *flowTable) queuePacket(p packetInfo, appID string, pkt []byte) (token string, queued bool, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return "", false, errors.New("隧道已关闭")
	}
	now := t.now()
	var f *flow
	if p.offset != 0 {
		s, ok := t.fragments[p.fragment]
		if !ok {
			return "", false, ErrFragmentMissing
		}
		if !now.Before(s.expiresAt) || t.flows[s.flow.key] != s.flow || s.flow.state == flowFailed || t.expired(s.flow, now) {
			delete(t.fragments, p.fragment)
			return "", false, ErrFragmentMissing
		}
		if p.offset != s.nextOffset {
			delete(t.fragments, p.fragment)
			return "", false, ErrFragmentOrder
		}
		f = s.flow
	} else {
		if p.more {
			if s, exists := t.fragments[p.fragment]; exists {
				delete(t.fragments, p.fragment)
				if now.Before(s.expiresAt) {
					return "", false, ErrFragmentOrder
				}
			}
			t.expireFragmentsLocked(now)
			if len(t.fragments) >= maxFragments {
				return "", false, ErrFragmentFull
			}
		}
		f = t.flows[p.key]
		if f != nil && t.expired(f, now) {
			t.removeLocked(f)
			f = nil
		}
		if f == nil {
			if len(t.flows) >= maxFlows {
				return "", false, ErrFlowTableFull
			}
			if t.pendingPackets >= maxPendingPackets || t.pendingBytes+len(pkt) > maxPendingBytes {
				return "", false, ErrPendingFull
			}
			t.next++
			f = &flow{key: p.key, appID: appID, authID: t.next, state: flowPending, createdAt: now, updatedAt: now}
			t.flows[f.key], t.auth[f.authID] = f, f
		}
	}
	f.updatedAt = now
	switch f.state {
	case flowFailed:
		delete(t.fragments, p.fragment)
		return "", false, ErrFlowRejected
	case flowPending:
		if len(f.pending) >= maxPendingPerFlow || t.pendingPackets >= maxPendingPackets || t.pendingBytes+len(pkt) > maxPendingBytes {
			delete(t.fragments, p.fragment)
			return "", false, ErrPendingFull
		}
		cp := append([]byte(nil), pkt...)
		f.pending = append(f.pending, cp)
		t.pendingPackets++
		t.pendingBytes += len(cp)
		queued = true
	case flowReady:
		token = f.token
	default:
		panic("非法流状态")
	}
	if p.more {
		if p.offset == 0 {
			t.fragments[p.fragment] = fragmentState{flow: f, expiresAt: now.Add(fragmentTTL), nextOffset: p.payloadBytes}
		} else {
			s := t.fragments[p.fragment]
			s.nextOffset = p.offset + p.payloadBytes
			t.fragments[p.fragment] = s
		}
	} else if p.offset != 0 {
		delete(t.fragments, p.fragment)
	}
	return token, queued, nil
}
func (t *flowTable) pendingAuth(limit int) []authFlow {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]authFlow, 0, limit)
	now := t.now()
	for _, f := range t.flows {
		if t.expired(f, now) {
			t.removeLocked(f)
			continue
		}
		if f.state == flowPending && f.authSent.IsZero() &&
			(f.authRetryAt.IsZero() || !now.Before(f.authRetryAt)) {
			f.authSent = now
			out = append(out, authFlow{key: f.key, appID: f.appID, authID: f.authID})
			if len(out) == limit {
				break
			}
		}
	}
	return out
}

// retryAuth 保留当前流与缓存，最多安排一次延迟重试。等待期间的重复临时
// 响应不续期；成功响应仍可完成第一次请求，未发送过请求的流不接受响应。
func (t *flowTable) retryAuth(authID uint64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	f := t.auth[authID]
	if f == nil || f.state != flowPending || f.authSent.IsZero() && f.authRetryAt.IsZero() {
		return false
	}
	now := t.now()
	if t.expired(f, now) {
		t.removeLocked(f)
		return false
	}
	if !f.authRetryAt.IsZero() {
		return f.authSent.IsZero()
	}
	f.authRetryAt = now.Add(flowAuthRetryDelay)
	f.authSent = time.Time{}
	f.updatedAt = now
	return true
}

func (t *flowTable) releasePendingLocked(f *flow) [][]byte {
	packets := f.pending
	for _, pkt := range packets {
		t.pendingBytes -= len(pkt)
	}
	t.pendingPackets -= len(packets)
	f.pending = nil
	return packets
}
func (t *flowTable) completeAuth(authID uint64, token string, authErr error) (flowKey, [][]byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	f := t.auth[authID]
	if f == nil || f.state != flowPending || f.authSent.IsZero() && f.authRetryAt.IsZero() {
		return flowKey{}, nil
	}
	now := t.now()
	if t.expired(f, now) {
		t.removeLocked(f)
		return flowKey{}, nil
	}
	packets := t.releasePendingLocked(f)
	f.updatedAt = now
	if authErr != nil || len(token) == 0 || len(token) > 255 {
		f.state = flowFailed
		t.removeFragmentsLocked(f)
		return f.key, nil
	}
	f.state, f.token = flowReady, token
	return f.key, packets
}
func (t *flowTable) expired(f *flow, now time.Time) bool {
	if f.state == flowPending {
		deadline := f.createdAt.Add(flowAuthTimeout)
		if !f.authRetryAt.IsZero() {
			// 首次最多等待 8 秒，延迟 10 秒后重试窗口仍为 8 秒；总计最多 26 秒。
			deadline = f.authRetryAt.Add(flowAuthTimeout)
		}
		return !now.Before(deadline)
	}
	return !now.Before(f.updatedAt.Add(flowIdleTTL))
}
func (t *flowTable) removeFragmentsLocked(f *flow) {
	for key, s := range t.fragments {
		if s.flow == f {
			delete(t.fragments, key)
		}
	}
}
func (t *flowTable) removeLocked(f *flow) {
	t.releasePendingLocked(f)
	delete(t.flows, f.key)
	delete(t.auth, f.authID)
	t.removeFragmentsLocked(f)
}
func (t *flowTable) expireFragmentsLocked(now time.Time) {
	for key, s := range t.fragments {
		if !now.Before(s.expiresAt) {
			delete(t.fragments, key)
		}
	}
}
func (t *flowTable) expire(now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	count := 0
	for _, f := range t.flows {
		if t.expired(f, now) {
			// 批量回收后只扫描一次分片表，避免 flows × fragments 次比较。
			t.releasePendingLocked(f)
			delete(t.flows, f.key)
			delete(t.auth, f.authID)
			count++
		}
	}
	for key, s := range t.fragments {
		if !now.Before(s.expiresAt) || t.flows[s.flow.key] != s.flow {
			delete(t.fragments, key)
		}
	}
	return count
}
func (t *flowTable) clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	clear(t.flows)
	clear(t.auth)
	clear(t.fragments)
	t.closed = true
	t.pendingPackets, t.pendingBytes = 0, 0
}

func (t *flowTable) rejectFragment(key fragmentKey) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.fragments, key)
}
