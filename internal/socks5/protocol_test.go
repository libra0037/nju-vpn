package socks5

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/ztna"
)

func TestMethodAndPasswordNegotiationFixedBytes(t *testing.T) {
	for _, tc := range []struct {
		name          string
		auth          bool
		request, want []byte
		success       bool
	}{
		{"none", false, []byte{5, 2, 2, 0}, []byte{5, 0}, true},
		{"not-offered", false, []byte{5, 1, 2}, []byte{5, 255}, false},
		{"password", true, []byte{5, 2, 0, 2, 1, 1, 'u', 1, 'p'}, []byte{5, 2, 1, 0}, true},
		{"wrong", true, []byte{5, 1, 2, 1, 1, 'u', 1, 'x'}, []byte{5, 2, 1, 1}, false},
		{"auth-no-downgrade", true, []byte{5, 1, 0}, []byte{5, 255}, false},
		{"empty-user", true, []byte{5, 1, 2, 1, 0}, []byte{5, 2, 1, 1}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := New("127.0.0.1:0", Options{Username: map[bool]string{true: "u"}[tc.auth], Password: map[bool]string{true: "p"}[tc.auth], MaxConnections: 1, MaxDials: 1})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			var out bytes.Buffer
			err = s.negotiate(oneByteReader{bytes.NewReader(tc.request)}, &out)
			if (err == nil) != tc.success || !bytes.Equal(out.Bytes(), tc.want) {
				t.Fatal("固定协商字节错误", out.Bytes(), err)
			}
			if err != nil && strings.Contains(err.Error(), "credential-marker") {
				t.Fatal("凭据泄露")
			}
		})
	}
}

type oneByteReader struct{ io.Reader }

func (r oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.Reader.Read(p)
}

func runProxy(t *testing.T, opts Options, dial DialFunc) *Server {
	t.Helper()
	s, err := New("127.0.0.1:0", opts)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Run(t.Context(), dial) }()
	select {
	case <-s.Started():
	case <-time.After(time.Second):
		t.Fatal("未启动")
	}
	t.Cleanup(func() {
		s.Close()
		if err := <-done; err != nil {
			t.Error("关闭失败", err)
		}
	})
	return s
}
func connectProxy(t *testing.T, s *Server) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp4", s.listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(2 * time.Second))
	return c
}

func TestUnsupportedAndMalformedRequestsNeverDial(t *testing.T) {
	s := runProxy(t, Options{MaxConnections: 4, MaxDials: 1}, func(context.Context, ztna.TCPTarget) (Stream, error) {
		t.Error("拒绝请求仍拨号")
		return nil, errors.New("unexpected")
	})
	for _, tc := range []struct {
		request []byte
		code    byte
	}{
		{[]byte{5, 2, 0, 1, 192, 0, 2, 1, 0, 80}, 7}, {[]byte{5, 3, 0, 1, 192, 0, 2, 1, 0, 80}, 7},
		{[]byte{5, 1, 0, 4}, 8}, {[]byte{5, 1, 1, 1}, 1}, {[]byte{4, 1, 0, 1}, 1},
		{[]byte{5, 1, 0, 3, 0}, 8}, {[]byte{5, 1, 0, 1, 192, 0, 2, 1, 0, 0}, 8},
		{[]byte{5, 1, 0, 3, 3, 'a', '\n', 'b', 0, 80}, 8},
	} {
		c := connectProxy(t, s)
		if _, err := c.Write(append([]byte{5, 1, 0}, tc.request...)); err != nil {
			t.Fatal(err)
		}
		var method [2]byte
		if _, err := io.ReadFull(c, method[:]); err != nil || method != [2]byte{5, 0} {
			t.Fatal(err)
		}
		var reply [10]byte
		if _, err := io.ReadFull(c, reply[:]); err != nil || !bytes.Equal(reply[:], []byte{5, tc.code, 0, 1, 0, 0, 0, 0, 0, 0}) {
			t.Fatal("拒绝响应字节错误", reply, err)
		}
		c.Close()
	}
}

func TestConnectionAndDialBudgetsCancelAndJoin(t *testing.T) {
	entered := make(chan struct{}, 1)
	var active atomic.Int32
	s := runProxy(t, Options{MaxConnections: 2, MaxDials: 1}, func(ctx context.Context, _ ztna.TCPTarget) (Stream, error) {
		active.Add(1)
		defer active.Add(-1)
		entered <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	})
	first := connectProxy(t, s)
	_, _ = first.Write([]byte{5, 1, 0, 5, 1, 0, 1, 192, 0, 2, 1, 0, 80})
	var method [2]byte
	if _, err := io.ReadFull(first, method[:]); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("建连未开始")
	}
	second := connectProxy(t, s)
	_, _ = second.Write([]byte{5, 1, 0})
	if _, err := io.ReadFull(second, method[:]); err != nil {
		t.Fatal(err)
	}
	third := connectProxy(t, s)
	var octet [1]byte
	if _, err := third.Read(octet[:]); err == nil {
		t.Fatal("超限接入未拒绝")
	}
	_, _ = second.Write([]byte{5, 1, 0, 1, 192, 0, 2, 1, 0, 80})
	var reply [10]byte
	if _, err := io.ReadFull(second, reply[:]); err != nil || reply[1] != 1 {
		t.Fatal("建连上限未拒绝", err, reply)
	}
	s.Close()
	if d := s.Diagnostics(); active.Load() != 0 || d.Listening || d.Connections != 0 || d.Dialing != 0 || d.Rejected < 2 {
		t.Fatal("关闭未等待或预算无诊断", d, active.Load())
	}
}

func TestHandshakeTimeoutAndConstructorConstraints(t *testing.T) {
	for _, opts := range []Options{{MaxConnections: 0, MaxDials: 1}, {MaxConnections: 1, MaxDials: 2}, {MaxConnections: 1, MaxDials: 1, Username: "u"}, {MaxConnections: 1, MaxDials: 1, HandshakeTimeout: -1}} {
		if s, err := New("127.0.0.1:0", opts); err == nil {
			s.Close()
			t.Fatal("非法参数被接受")
		}
	}
	if s, err := New("0.0.0.0:0", Options{MaxConnections: 1, MaxDials: 1}); err == nil {
		s.Close()
		t.Fatal("非回环允许匿名访问")
	}
	s := runProxy(t, Options{MaxConnections: 1, MaxDials: 1, HandshakeTimeout: 20 * time.Millisecond}, func(context.Context, ztna.TCPTarget) (Stream, error) {
		t.Error("未握手仍拨号")
		return nil, errors.New("unexpected")
	})
	c := connectProxy(t, s)
	var octet [1]byte
	if _, err := c.Read(octet[:]); err == nil {
		t.Fatal("停滞握手未结束")
	}
}

func TestReplyCodeIsStableAndDoesNotDependOnErrorText(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code byte
	}{
		{ztna.ErrTCPResourceUnmatched, 2}, {ztna.ErrTCPAuthRejected, 2}, {ztna.ErrTCPAddressUnsupported, 8},
		{&ztna.TCPConnectError{Reply: 5}, 5}, {context.DeadlineExceeded, 4}, {syscall.ECONNREFUSED, 5}, {syscall.ENETUNREACH, 3}, {syscall.EHOSTUNREACH, 4}, {errors.New("connection refused"), 1},
	} {
		if got := replyCode(tc.err); got != tc.code {
			t.Fatal("错误映射不稳定", got, tc.code)
		}
	}
}
