package ztna

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"
)

// 2026-10-01 实机返回 05 93 86、code=10000008；替换真实令牌，固定帧长为 69。
const temporaryAuthFrame = "\x05\x93\x86\x00\x45" +
	`{"code":10000008,"data":{"conntrackHash":1,"connectToken":"pending"}}`

func pendingAuthFixture(t *testing.T, clock func() time.Time) (*flowTable, packetInfo, []byte) {
	t.Helper()
	ft := newFlowTableWithClock(clock)
	pkt := []byte{0x45, 0, 0, 28, 0, 1, 0, 0, 64, 17, 0, 0, 10, 66, 66, 2, 192, 0, 2, 1, 0x9c, 0x40, 1, 0xbb, 0, 8, 0, 0}
	p, err := parsePacket(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if _, queued, err := ft.queuePacket(p, "app", pkt); err != nil || !queued {
		t.Fatal("首包未缓存", queued, err)
	}
	if auth := ft.pendingAuth(1); len(auth) != 1 || auth[0].authID != 1 {
		t.Fatal("首包未产生可关联的鉴权请求", auth)
	}
	return ft, p, pkt
}

func TestTemporaryAuthResponseRetriesOnce(t *testing.T) {
	now := time.Unix(1700000000, 0)
	ft, p, pkt := pendingAuthFixture(t, func() time.Time { return now })
	fr, err := readFrame(bufio.NewReader(bytes.NewBufferString(temporaryAuthFrame)))
	if err != nil || fr.cmd != 0x93 || fr.status != 0x86 {
		t.Fatal("固定临时鉴权帧解析失败", fr, err)
	}
	tc := &tunnelConn{flows: ft, logf: func(string, ...any) {}}
	tc.handleAuthResp(fr.status, fr.payload)
	now = now.Add(9 * time.Second)
	if _, queued, err := ft.queuePacket(p, "app", pkt); err != nil || !queued {
		t.Fatal("临时状态被当成永久失败，或等待窗口过早结束", queued, err)
	}
	if requests := ft.pendingAuth(1); len(requests) != 0 {
		t.Fatal("未等满 10 秒就重试", requests)
	}
	now = now.Add(time.Second)
	if requests := ft.pendingAuth(1); len(requests) != 1 || requests[0].authID != 1 {
		t.Fatal("10 秒后未重试当前流", requests)
	}
	if requests := ft.pendingAuth(1); len(requests) != 0 {
		t.Fatal("同一次重试被重复调度", requests)
	}
	tc.handleAuthResp(fr.status, fr.payload)
	if _, _, err := ft.queuePacket(p, "app", pkt); !errors.Is(err, ErrFlowRejected) {
		t.Fatal("第二次临时状态仍继续重试", err)
	}
	if ft.pendingPackets != 0 || ft.pendingBytes != 0 {
		t.Fatal("重试耗尽仍占用首包缓存")
	}
}

func TestAuthRetryCanAcceptFirstResponseDuringWait(t *testing.T) {
	now := time.Unix(1700000000, 0)
	ft, p, pkt := pendingAuthFixture(t, func() time.Time { return now })
	if !ft.retryAuth(1) {
		t.Fatal("未安排重试")
	}
	now = now.Add(9 * time.Second)
	_, packets := ft.completeAuth(1, "ready", nil)
	if len(packets) != 1 || !bytes.Equal(packets[0], pkt) {
		t.Fatal("等待重试期间的成功响应被丢弃", packets)
	}
	if token, queued, err := ft.queuePacket(p, "app", pkt); err != nil || queued || token != "ready" {
		t.Fatal("成功后未使用令牌", token, queued, err)
	}
	now = now.Add(time.Second)
	if requests := ft.pendingAuth(1); len(requests) != 0 {
		t.Fatal("成功后仍发起重试", requests)
	}
	if ft.retryAuth(1) || ft.retryAuth(999) {
		t.Fatal("已完成或未知流仍可安排重试")
	}
}

func TestAuthRetryDuplicateDoesNotExtendDeadline(t *testing.T) {
	now := time.Unix(1700000000, 0)
	ft, _, _ := pendingAuthFixture(t, func() time.Time { return now })
	if !ft.retryAuth(1) {
		t.Fatal("未安排重试")
	}
	now = now.Add(9 * time.Second)
	if !ft.retryAuth(1) {
		t.Fatal("等待期间的重复临时响应结束了当前流")
	}
	now = now.Add(time.Second)
	if requests := ft.pendingAuth(1); len(requests) != 1 {
		t.Fatal("重复响应推迟了原定重试", requests)
	}
	now = now.Add(8 * time.Second)
	if _, packets := ft.completeAuth(1, "late", nil); len(packets) != 0 {
		t.Fatal("重试窗口结束后仍接受响应")
	}
	if len(ft.flows) != 0 || len(ft.auth) != 0 || ft.pendingPackets != 0 || ft.pendingBytes != 0 {
		t.Fatal("重试超时未释放流与缓存")
	}
}

func TestAuthRetryWorstCaseBudgetAndClose(t *testing.T) {
	for _, finish := range []string{"expiry", "close"} {
		t.Run(finish, func(t *testing.T) {
			now := time.Unix(1700000000, 0)
			ft, _, _ := pendingAuthFixture(t, func() time.Time { return now })
			now = now.Add(8*time.Second - time.Nanosecond)
			if !ft.retryAuth(1) {
				t.Fatal("有效初始窗口内不能重试")
			}
			// 不执行重试调度，固定期限仍要释放；总等待不能超过 26 秒。
			now = now.Add(18 * time.Second)
			if finish == "close" {
				ft.clear()
			} else if requests := ft.pendingAuth(1); len(requests) != 0 {
				t.Fatal("26 秒后仍调度鉴权", requests)
			}
			if ft.retryAuth(1) {
				t.Fatal("关闭或过期后仍接受临时响应")
			}
			if _, packets := ft.completeAuth(1, "late", nil); len(packets) != 0 {
				t.Fatal("关闭或过期后仍接受成功响应")
			}
			if len(ft.flows) != 0 || ft.pendingPackets != 0 || ft.pendingBytes != 0 {
				t.Fatal("固定期限结束未释放缓存")
			}
		})
	}
}

func TestUnobservedAuthStatusesStillReject(t *testing.T) {
	for _, status := range []byte{0, 0x81, 0x84, 0x85, 0x87} {
		t.Run(fmt.Sprintf("%02X", status), func(t *testing.T) {
			now := time.Unix(1700000000, 0)
			ft, p, pkt := pendingAuthFixture(t, func() time.Time { return now })
			tc := &tunnelConn{flows: ft, logf: func(string, ...any) {}}
			tc.handleAuthResp(status, []byte(`{"code":10000008,"data":{"conntrackHash":1,"connectToken":"pending"}}`))
			if _, _, err := ft.queuePacket(p, "app", pkt); !errors.Is(err, ErrFlowRejected) {
				t.Fatal("其他状态或非零 code 未被拒绝", status, err)
			}
		})
	}
}

func TestInitialAuthDeadlineRejectsLateResponse(t *testing.T) {
	now := time.Unix(1700000000, 0)
	ft, _, _ := pendingAuthFixture(t, func() time.Time { return now })
	now = now.Add(8 * time.Second)
	if ft.retryAuth(1) {
		t.Fatal("过期首请求仍可延长等待")
	}
	if _, packets := ft.completeAuth(1, "late", nil); len(packets) != 0 {
		t.Fatal("过期首请求仍接受成功响应")
	}
	if len(ft.flows) != 0 || ft.pendingPackets != 0 || ft.pendingBytes != 0 {
		t.Fatal("首请求过期未释放缓存")
	}
}
