package service

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/ipc"
	"github.com/libra0037/nju-vpn/internal/ztna"
	"github.com/libra0037/nju-vpn/internal/ztnatest"
)

func TestResourcesReadsCurrentSessionWithoutSideEffects(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(map[bool]string{true: "empty", false: "apps"}[empty], func(t *testing.T) {
			opts := ztnatest.Options{}
			if empty {
				opts.Apps = []ztnatest.App{}
			}
			srv := newFakeServer(t, opts)
			svc := newTestService(t, srv, newTestConfig(t, srv))
			server := NewServer(svc, nil)
			if r := server.dispatch(ipc.Request{Command: ipc.CmdResources}); r.Code != 409 {
				t.Fatal("未登录仍有快照", r)
			}
			if err := svc.Start(false, ""); err != nil {
				t.Fatal(err)
			}
			calls, tunnels, sms, logouts := srv.ResourceCalls(), srv.Tunnels(), srv.SMSSends(), srv.LogoutCount()
			for range 3 {
				r := server.dispatch(ipc.Request{Command: ipc.CmdResources})
				if r.Code != 200 {
					t.Fatal(r)
				}
				var list ztna.L3Resources
				if err := json.Unmarshal([]byte(r.Message), &list); err != nil || list.IP == nil || list.NodeGroup == nil {
					t.Fatal("无效快照", r)
				}
				if empty && len(list.IP) != 0 || !empty && len(list.IP) != 1 {
					t.Fatal("快照丢失", list)
				}
			}
			if calls != srv.ResourceCalls() || tunnels != srv.Tunnels() || sms != srv.SMSSends() || logouts != srv.LogoutCount() {
				t.Fatal("资源查询触发控制面或隧道副作用")
			}
			if r := server.dispatch(ipc.Request{Command: ipc.CmdResources, Args: []string{"unexpected"}}); r.Code != 400 {
				t.Fatal("未拒绝参数")
			}
			if err := svc.Stop(); err != nil {
				t.Fatal(err)
			}
			if r := server.dispatch(ipc.Request{Command: ipc.CmdResources}); r.Code != 409 {
				t.Fatal("停止后仍有旧快照")
			}
		})
	}
}
func TestCommandDeadlineCancelsOperationAndExpiredQueueIsSkipped(t *testing.T) {
	srv := newFakeServer(t, ztnatest.Options{})
	entered := make(chan struct{}, 1)
	var calls atomic.Int32
	fn := func(ctx context.Context, _, _ string) (net.Conn, error) {
		calls.Add(1)
		select {
		case entered <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	svc := newTestService(t, srv, newTestConfig(t, srv), Options{Dial: fn, CommandTimeout: 80 * time.Millisecond})
	done := make(chan error, 1)
	go func() { done <- svc.Start(false, "") }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("操作未开始")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("命令总预算无效")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	cmd := &command{kind: cmdStart, ctx: ctx, reply: make(chan error, 1)}
	svc.cmds <- cmd
	select {
	case err := <-cmd.reply:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("过期命令未回复")
	}
	if calls.Load() != 1 {
		t.Fatal("过期排队命令仍发起网络操作", calls.Load())
	}
}
func TestIllegalStatusTransitionIsGuarded(t *testing.T) {
	st := newStatusStore(Identity{})
	defer func() {
		if recover() == nil {
			t.Fatal("非法 idle → up 未断言")
		}
		if st.Get().State != StateIdle {
			t.Fatal("非法迁移改变状态")
		}
	}()
	st.set(StateUp, "")
}

func TestStopIsNotLostWhenCommandQueueIsFull(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	svc := &Service{cmds: make(chan *command, 1), closed: make(chan struct{}), commandTimeout: time.Second, opCancel: cancel}
	svc.cmds <- &command{kind: cmdStart}
	done := make(chan error, 1)
	go func() { done <- svc.Stop() }()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("Stop 未取消当前操作")
	}
	select {
	case err := <-done:
		t.Fatal("队列满时丢失 Stop", err)
	default:
	}
	<-svc.cmds
	select {
	case cmd := <-svc.cmds:
		if cmd.kind != cmdStop {
			t.Fatal("没有接收停止命令")
		}
		cmd.reply <- nil
	case <-time.After(time.Second):
		t.Fatal("队列释放后 Stop 未入队")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
