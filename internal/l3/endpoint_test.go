package l3

import (
	"errors"
	"sync"
	"testing"
)

func TestSendWithoutUplink(t *testing.T) {
	ep := New()
	if err := ep.Send([]byte("x")); !errors.Is(err, ErrNoUplink) {
		t.Errorf("没有上行通道时 Send 应报 ErrNoUplink，得到 %v", err)
	}
	// 没有下行回调时投递必须是安全的：隧道协程会在会话刚摘掉时投包。
	ep.Deliver([]byte("x"))
}

func TestUplinkAndDownlink(t *testing.T) {
	ep := New()
	var mu sync.Mutex
	var sent [][]byte
	ep.SetUplink(func(b []byte) error {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, append([]byte(nil), b...))
		return nil
	})
	ep.SetDownlink(func(b []byte) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, append([]byte(nil), b...))
	})

	if err := ep.Send([]byte("up")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	ep.Deliver([]byte("down"))

	mu.Lock()
	defer mu.Unlock()
	if len(sent) != 1 || string(sent[0]) != "up" {
		t.Errorf("上行 = %v", sent)
	}
	if len(got) != 1 || string(got[0]) != "down" {
		t.Errorf("下行 = %v", got)
	}
}

func TestClearUplinkStopsDelivery(t *testing.T) {
	ep := New()
	called := 0
	ep.SetUplink(func([]byte) error { called++; return nil })
	ep.ClearUplink()
	if err := ep.Send([]byte("x")); !errors.Is(err, ErrNoUplink) {
		t.Errorf("注销后 Send 应报 ErrNoUplink，得到 %v", err)
	}
	if called != 0 {
		t.Errorf("注销之后不该再调用上行回调，调用了 %d 次", called)
	}
}

func TestConcurrentSwap(t *testing.T) {
	ep := New()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			ep.SetUplink(func([]byte) error { return nil })
			ep.Send([]byte("x"))
			ep.ClearUplink()
		}
	}()
	for i := 0; i < 200; i++ {
		ep.SetDownlink(func([]byte) {})
		ep.Deliver([]byte("y"))
		ep.ClearDownlink()
	}
	<-done
}

// got 是下行方向的收集器，单独放是因为上面的闭包要在解析前声明。
var got [][]byte
