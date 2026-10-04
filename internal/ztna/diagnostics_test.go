package ztna

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/ztnatest"
)

func TestTunnelUsesConfiguredMTUAndCopiesDiagnostics(t *testing.T) {
	srv := newFake(t, ztnatest.Options{})
	client := newTestClient(t, srv, testPass)
	client.opts.MTU = 1500
	sess, err := client.Connect(t.Context(), ConnectOptions{})
	if sess != nil {
		t.Cleanup(func() { sess.Close(context.Background()) })
	}
	if err != nil {
		t.Fatal(err)
	}
	packet := ipv4TCP("172.16.0.9", "10.1.2.3", 30000, 443, bytes.Repeat([]byte{0xa5}, 1460))
	if len(packet) != 1500 {
		t.Fatal("独立包样例长度错误")
	}
	if err := sess.Endpoint().Send(packet); err != nil {
		t.Fatalf("1500 字节包应按配置接受: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(srv.Uplink()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	packets := srv.Uplink()
	if len(packets) != 1 || !bytes.Equal(packets[0], packet) {
		t.Fatal("校园隧道未透明转发 1500 字节包")
	}
	tooLarge := ipv4TCP("172.16.0.9", "10.1.2.3", 30000, 443, make([]byte, 1461))
	if err := sess.Endpoint().Send(tooLarge); !errors.Is(err, ErrPacketTooLarge) {
		t.Fatal("超配置 MTU 未拒绝", err)
	}
	if err := sess.Endpoint().Send(ipv4TCP("172.16.0.9", "192.0.2.1", 30000, 443, nil)); !errors.Is(err, ErrResourceUnmatched) {
		t.Fatal(err)
	}
	diag := sess.Diagnostics()
	if !diag.Connected || diag.MTU != 1500 || diag.Rejected.MTUExceeded != 1 || diag.Rejected.ResourceUnmatched != 1 {
		t.Fatalf("诊断未反映真实拒绝: %+v", diag)
	}
	diag.Rejected.MTUExceeded = 99
	if sess.Diagnostics().Rejected.MTUExceeded != 1 {
		t.Fatal("查询结果可修改内部计数")
	}
}

func TestRejectionCountersAreFiniteAndConcurrent(t *testing.T) {
	conn := &tunnelConn{}
	var workers sync.WaitGroup
	for _, err := range []error{ErrResourceUnmatched, ErrFlowRejected, ErrPendingFull, ErrFlowTableFull, ErrFragmentMissing, ErrFragmentOrder, ErrFragmentFull, ErrPacketTooLarge, &ProtocolError{What: "invalid"}, errors.New("link")} {
		workers.Go(func() {
			for range 100 {
				conn.recordRejection(err)
			}
		})
	}
	workers.Wait()
	want := RejectionCounts{100, 100, 100, 100, 100, 100, 100, 100, 100, 100}
	if conn.rejected != want {
		t.Fatalf("分类计数有遗漏: %+v", conn.rejected)
	}
}
