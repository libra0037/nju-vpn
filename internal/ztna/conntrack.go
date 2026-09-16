package ztna

import (
	"sync"
	"time"
)

// 逐流鉴权：服务端要求每条新流先单独申请一个会话令牌，拿到令牌之后
// 该流的数据包才被转发。没拿到令牌就发的包会被丢掉，所以首包要缓存。

type flowState uint8

const (
	flowPending flowState = iota // 等待鉴权结果
	flowReady                    // 已有令牌
	flowFailed                   // 鉴权失败，丢弃该流的包
)

const (
	// 一条流在多久没有数据后被回收。
	flowIdleTTL = 2 * time.Minute
	// 鉴权请求发出后等多久算超时。
	flowAuthTimeout = 8 * time.Second
	// 单条流最多缓存多少个待发首包：认证期间上游可能连发几个包，
	// 但无限缓存会让一条卡住的流吃光内存。
	maxPendingPerFlow = 64
	// 流表条目上限，防止异常流量把内存撑爆。
	maxFlows = 8192
)

type flow struct {
	key     flowKey
	appID   string
	groupID string

	authID uint64
	token  string
	state  flowState
	err    error

	pending  [][]byte
	authSent time.Time

	createdAt time.Time
	updatedAt time.Time
}

func (f *flow) expired(now time.Time) bool {
	if f.state == flowPending && !f.authSent.IsZero() && now.Sub(f.authSent) > flowAuthTimeout {
		return true
	}
	return now.Sub(f.updatedAt) > flowIdleTTL
}

// flowTable 是流表的并发封装。隧道协程与承载协程都会碰它，
// 因此所有访问都过互斥锁，且不做任何 I/O。
type flowTable struct {
	mu    sync.Mutex
	flows map[flowKey]*flow
	next  uint64
}

func newFlowTable() *flowTable {
	return &flowTable{flows: make(map[flowKey]*flow)}
}

// get 返回已有条目；没有就按 appID/groupID 建一条。
func (t *flowTable) get(key flowKey, appID, groupID string) *flow {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	if f, ok := t.flows[key]; ok {
		f.updatedAt = now
		return f
	}
	if len(t.flows) >= maxFlows {
		t.evictLocked(now)
	}
	t.next++
	f := &flow{
		key: key, appID: appID, groupID: groupID,
		authID: t.next, state: flowPending,
		createdAt: now, updatedAt: now,
	}
	t.flows[key] = f
	return f
}

// pendingAuth 返回所有等待发鉴权请求的流（每条流只发一次）。
func (t *flowTable) pendingAuth(limit int) []*flow {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []*flow
	for _, f := range t.flows {
		if f.state != flowPending || !f.authSent.IsZero() {
			continue
		}
		out = append(out, f)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func (t *flowTable) markAuthSent(key flowKey) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if f, ok := t.flows[key]; ok {
		f.authSent = time.Now()
	}
}

// completeAuth 记录鉴权结果，并交出该流缓存的待发包。
func (t *flowTable) completeAuth(authID uint64, token string, err error) (flowKey, [][]byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for key, f := range t.flows {
		if f.authID != authID {
			continue
		}
		f.updatedAt = time.Now()
		if err != nil {
			f.state = flowFailed
			f.err = err
			f.pending = nil
			return key, nil
		}
		f.state = flowReady
		f.token = token
		pending := f.pending
		f.pending = nil
		return key, pending
	}
	return flowKey{}, nil
}

// cache 缓存一个待发包，超过上限就丢弃最旧的。
func (t *flowTable) cache(key flowKey, pkt []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	f, ok := t.flows[key]
	if !ok {
		return
	}
	if len(f.pending) >= maxPendingPerFlow {
		f.pending = f.pending[1:]
	}
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	f.pending = append(f.pending, cp)
}

func (t *flowTable) token(key flowKey) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	f, ok := t.flows[key]
	if !ok || f.state != flowReady {
		return "", false
	}
	return f.token, true
}

// expire 回收超时条目，返回回收的数量。
func (t *flowTable) expire(now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for key, f := range t.flows {
		if f.expired(now) {
			delete(t.flows, key)
			n++
		}
	}
	return n
}

func (t *flowTable) evictLocked(now time.Time) {
	// 先删彻底过期的；还不够就删最久没动的。
	if t.expireLocked(now) == 0 {
		var oldestKey flowKey
		var oldest time.Time
		for key, f := range t.flows {
			if oldest.IsZero() || f.updatedAt.Before(oldest) {
				oldest, oldestKey = f.updatedAt, key
			}
		}
		delete(t.flows, oldestKey)
	}
}

func (t *flowTable) expireLocked(now time.Time) int {
	n := 0
	for key, f := range t.flows {
		if f.expired(now) {
			delete(t.flows, key)
			n++
		}
	}
	return n
}
