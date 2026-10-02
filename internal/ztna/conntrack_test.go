package ztna

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"
)

// 首片包含完整 UDP 头，尾片的 0xff 开头故意不像任何传输头。
// 不使用被测编解码器生成期望值。
func udpFragment(id uint16, offset uint16, more bool, size int) []byte {
	p := make([]byte, 20+size)
	copy(p, []byte{0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2})
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	binary.BigEndian.PutUint16(p[4:6], id)
	flags := offset
	if more {
		flags |= 0x2000
	}
	binary.BigEndian.PutUint16(p[6:8], flags)
	for i := 20; i < len(p); i++ {
		p[i] = 0xff
	}
	if offset == 0 && size >= 8 {
		copy(p[20:28], []byte{0x9c, 0x40, 0x01, 0xbb, 0, 32, 0, 0})
	}
	return p
}
func queueFragment(t *testing.T, f *flowTable, pkt []byte) (string, bool, error) {
	t.Helper()
	p, err := parsePacket(pkt)
	if err != nil {
		t.Fatal(err)
	}
	return f.queuePacket(p, "app-a", pkt)
}

func TestFragmentSequenceCompletesWhileAuthenticationPending(t *testing.T) {
	ft := newFlowTable()
	first := udpFragment(9, 0, true, 16)
	middle := udpFragment(9, 2, true, 8)
	last := udpFragment(9, 3, false, 8)
	for _, p := range [][]byte{first, middle, last} {
		token, queued, err := queueFragment(t, ft, p)
		if err != nil || !queued || token != "" {
			t.Fatalf("分片未缓存：%v %v %q", err, queued, token)
		}
	}
	if len(ft.fragments) != 0 {
		t.Fatal("末片接受后仍保留关联")
	}
	auth := ft.pendingAuth(2)
	if len(auth) != 1 {
		t.Fatalf("尾片另建了流：%d", len(auth))
	}
	if auth[0].key.sport != 40000 || auth[0].key.dport != 443 {
		t.Fatal("把尾片载荷当成端口")
	}
	_, packets := ft.completeAuth(auth[0].authID, "token-a", nil)
	if len(packets) != 3 {
		t.Fatalf("鉴权后少发包：%d", len(packets))
	}
	for i, p := range [][]byte{first, middle, last} {
		if !bytes.Equal(p, packets[i]) {
			t.Fatal("分片次序或内容变化")
		}
	}
	if ft.pendingPackets != 0 || ft.pendingBytes != 0 {
		t.Fatal("缓存预算未释放")
	}
	// 没有完成后的保留键，重复尾片必须拒绝。
	if _, _, err := queueFragment(t, ft, last); !errors.Is(err, ErrFragmentMissing) {
		t.Fatal(err)
	}
}

func TestFragmentFixedDeadlineAndImmediateReuse(t *testing.T) {
	now := time.Unix(1700000000, 0)
	ft := newFlowTableWithClock(func() time.Time { return now })
	first := udpFragment(3, 0, true, 16)
	queueFragment(t, ft, first)
	now = now.Add(4 * time.Second)
	if _, _, err := queueFragment(t, ft, udpFragment(3, 2, true, 8)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if _, _, err := queueFragment(t, ft, udpFragment(3, 3, false, 8)); !errors.Is(err, ErrFragmentMissing) {
		t.Fatalf("尾片续期：%v", err)
	}
	if len(ft.fragments) != 0 {
		t.Fatal("过期关联未删除")
	}
	// 同一 Identification 可立即开始新报文。
	if _, _, err := queueFragment(t, ft, first); err != nil {
		t.Fatal(err)
	}
	if _, _, err := queueFragment(t, ft, udpFragment(3, 2, false, 16)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := queueFragment(t, ft, first); err != nil {
		t.Fatal("完成后仍有冷却期", err)
	}
}

func TestFragmentFailuresClearAssociation(t *testing.T) {
	tests := []struct {
		name string
		next []byte
		want error
	}{
		{"缺首片", udpFragment(2, 2, false, 16), ErrFragmentMissing},
		{"空隙", udpFragment(1, 3, false, 8), ErrFragmentOrder},
		{"重叠", udpFragment(1, 1, false, 16), ErrFragmentOrder},
		{"重复首片", udpFragment(1, 0, true, 16), ErrFragmentOrder},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ft := newFlowTable()
			if tt.name != "缺首片" {
				queueFragment(t, ft, udpFragment(1, 0, true, 16))
			}
			if _, _, err := queueFragment(t, ft, tt.next); !errors.Is(err, tt.want) {
				t.Fatalf("want %v, got %v", tt.want, err)
			}
			if len(ft.fragments) != 0 {
				t.Fatal("拒绝后仍留关联")
			}
		})
	}
	t.Run("鉴权失败", func(t *testing.T) {
		ft := newFlowTable()
		queueFragment(t, ft, udpFragment(1, 0, true, 16))
		a := ft.pendingAuth(1)[0]
		ft.completeAuth(a.authID, "", errors.New("拒绝"))
		if len(ft.fragments) != 0 || ft.pendingBytes != 0 {
			t.Fatal("鉴权失败仍留关联或缓存")
		}
	})
	t.Run("关闭", func(t *testing.T) {
		ft := newFlowTable()
		queueFragment(t, ft, udpFragment(1, 0, true, 16))
		ft.clear()
		if len(ft.fragments) != 0 || len(ft.flows) != 0 || ft.pendingBytes != 0 {
			t.Fatal("关闭未清空")
		}
		if _, _, err := queueFragment(t, ft, udpFragment(1, 0, true, 16)); err == nil {
			t.Fatal("关闭后可接收")
		}
	})
}

func TestFragmentCapacityRejectsNewWithoutEviction(t *testing.T) {
	ft := newFlowTable()
	for i := 0; i < maxFragments; i++ {
		if _, _, err := queueFragment(t, ft, udpFragment(uint16(i), 0, true, 16)); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			a := ft.pendingAuth(1)[0]
			ft.completeAuth(a.authID, "ready", nil)
		}
	}
	before := ft.pendingPackets
	if _, _, err := queueFragment(t, ft, udpFragment(maxFragments, 0, true, 16)); !errors.Is(err, ErrFragmentFull) {
		t.Fatal(err)
	}
	if len(ft.fragments) != maxFragments || ft.pendingPackets != before {
		t.Fatal("溢出发生淘汰或缓存")
	}
	if _, _, err := queueFragment(t, ft, udpFragment(0, 2, false, 16)); err != nil {
		t.Fatal("活跃关联被淘汰", err)
	}
	if _, _, err := queueFragment(t, ft, udpFragment(maxFragments, 0, true, 16)); err != nil {
		t.Fatal("完成释放的名额未复用", err)
	}
}

func TestPacketFragmentBoundaryRejections(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"保留标志", func(p []byte) []byte { p[6] |= 0x80; return p }},
		{"DF 分片", func(p []byte) []byte { p[6] |= 0x40; return p }},
		{"IP 选项", func(p []byte) []byte { p[0] = 0x46; return p }},
		{"ICMP 分片", func(p []byte) []byte { p[9] = 1; return p }},
		{"未对齐", func(p []byte) []byte { p = p[:len(p)-1]; binary.BigEndian.PutUint16(p[2:4], uint16(len(p))); return p }},
		{"偏移越界", func(p []byte) []byte { p[6] = 0x1f; p[7] = 0xff; return p }},
		{"UDP 首片头不全", func(p []byte) []byte { p = p[:24]; binary.BigEndian.PutUint16(p[2:4], 24); return p }},
		{"TCP 首片头不全", func(p []byte) []byte { p[9] = 6; return p }},
		{"TCP 选项不全", func(p []byte) []byte {
			p = append(p, make([]byte, 8)...)
			binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
			p[9] = 6
			p[32] = 0xa0
			return p
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parsePacket(tt.mutate(udpFragment(1, 0, true, 16))); err == nil {
				t.Fatal("非法分片被接受")
			}
		})
	}
	tail, err := parsePacket(udpFragment(1, 2, false, 1))
	if err != nil || tail.srcPort != 0 || tail.dstPort != 0 {
		t.Fatal("尾片解析传输头", err)
	}
}

func TestAuthCompletionCannotStrandQueuedPacket(t *testing.T) {
	for _, phase := range []string{"initial", "retry-wait", "retry-sent"} {
		t.Run(phase, func(t *testing.T) {
			for i := 0; i < 100; i++ {
				now := time.Unix(1700000000, 0)
				ft := newFlowTableWithClock(func() time.Time { return now })
				pkt := udpFragment(1, 0, true, 16)
				p, _ := parsePacket(pkt)
				p.more = false // 测流表原子交接，不调用 Send 的字节解析。
				ft.queuePacket(p, "app", []byte{1})
				auth := ft.pendingAuth(1)[0]
				if phase != "initial" {
					if !ft.retryAuth(auth.authID) {
						t.Fatal("未安排重试")
					}
					now = now.Add(9 * time.Second)
					if phase == "retry-sent" {
						now = now.Add(time.Second)
						if len(ft.pendingAuth(1)) != 1 {
							t.Fatal("重试未发送")
						}
					}
				}
				barrier := make(chan struct{})
				var wg sync.WaitGroup
				var flushed [][]byte
				var token string
				var queued bool
				var err error
				wg.Go(func() { <-barrier; _, flushed = ft.completeAuth(auth.authID, "ready", nil) })
				wg.Go(func() { <-barrier; token, queued, err = ft.queuePacket(p, "app", []byte{2}) })
				close(barrier)
				wg.Wait()
				if err != nil {
					t.Fatal(err)
				}
				count := len(flushed)
				if !queued && token == "ready" {
					count++
				}
				if count != 2 || ft.pendingPackets != 0 || ft.pendingBytes != 0 {
					t.Fatalf("包被滞留：flushed=%v queued=%v token=%q", flushed, queued, token)
				}
			}
		})
	}
}

func TestPendingBudgetsRejectAndRecover(t *testing.T) {
	for _, kind := range []string{"per-flow", "packets", "bytes", "flows"} {
		t.Run(kind, func(t *testing.T) {
			ft := newFlowTable()
			pkt := bytes.Repeat([]byte{1}, 1000)
			p, _ := parsePacket(udpFragment(1, 0, true, 16))
			p.more = false
			var want error
			switch kind {
			case "per-flow":
				for i := 0; i < maxPendingPerFlow; i++ {
					ft.queuePacket(p, "app", pkt)
				}
				want = ErrPendingFull
			case "packets", "bytes":
				for i := 0; i < maxPendingPackets; i++ {
					p.key.sport = uint16(i)
					if kind == "bytes" {
						pkt = bytes.Repeat([]byte{1}, 1400)
					}
					if _, _, err := ft.queuePacket(p, "app", pkt); err != nil {
						break
					}
				}
				p.key.sport = 65535
				want = ErrPendingFull
			case "flows":
				for i := 0; i < maxFlows; i++ {
					k := p.key
					k.sport = uint16(i)
					ft.flows[k] = &flow{key: k, state: flowReady, token: "ready", createdAt: time.Now(), updatedAt: time.Now()}
				}
				p.key.sport = 65535
				want = ErrFlowTableFull
			}
			beforePackets, beforeBytes, beforeFlows := ft.pendingPackets, ft.pendingBytes, len(ft.flows)
			if _, _, err := ft.queuePacket(p, "app", pkt); !errors.Is(err, want) {
				t.Fatal(err)
			}
			if ft.pendingPackets != beforePackets || ft.pendingBytes != beforeBytes || len(ft.flows) != beforeFlows {
				t.Fatal("拒绝仍占预算或淘汰流")
			}
			ft.clear()
			if ft.pendingBytes != 0 || ft.pendingPackets != 0 {
				t.Fatal("关闭未释放预算")
			}
		})
	}
}

func BenchmarkReadyFlowPacket(b *testing.B) {
	ft := newFlowTable()
	pkt := udpFragment(1, 0, true, 16)
	p, _ := parsePacket(pkt)
	p.more = false
	ft.queuePacket(p, "app", pkt)
	a := ft.pendingAuth(1)[0]
	ft.completeAuth(a.authID, "ready", nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := ft.queuePacket(p, "app", pkt); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkExpireAtCapacity(b *testing.B) {
	now := time.Unix(1700000000, 0)
	ft := newFlowTableWithClock(func() time.Time { return now })
	for i := 0; i < maxFlows; i++ {
		k := flowKey{sport: uint16(i)}
		ft.flows[k] = &flow{key: k, state: flowReady, token: "r", updatedAt: now}
	}
	for i := 0; i < maxFragments; i++ {
		k := fragmentKey{id: uint16(i)}
		ft.fragments[k] = fragmentState{flow: ft.flows[flowKey{sport: uint16(i)}], expiresAt: now.Add(fragmentTTL)}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ft.expire(now)
	}
}
