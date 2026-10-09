package ztna

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHandshakeIOErrorsRedactAddressesAndKeepCauses(t *testing.T) {
	opts := stallOptions(t, 30*time.Millisecond)
	_, err := dialTunnel(t.Context(), opts)
	var timeout net.Error
	if err == nil || !errors.As(err, &timeout) || !timeout.Timeout() || strings.Contains(err.Error(), opts.Node) {
		t.Fatal("握手读错误未脱敏或丢失超时原因", err)
	}
	cause := &net.OpError{Op: "read", Net: "tcp", Source: &net.TCPAddr{IP: net.ParseIP("192.0.2.11"), Port: 1234}, Addr: &net.TCPAddr{IP: net.ParseIP("198.51.100.10"), Port: 441}, Err: io.ErrUnexpectedEOF}
	for _, prefix := range []string{"", "\x05\xd0", "\x05\xd0\x53\x00\x00\x0a", "\x05\xd0\x05\x00\x00\x01"} {
		_, err := readHandshake(bufio.NewReader(io.MultiReader(bytes.NewReader([]byte(prefix)), errorReader{cause})))
		if !errors.Is(err, io.ErrUnexpectedEOF) || strings.Contains(err.Error(), "198.51.100.10") || strings.Contains(err.Error(), "192.0.2.11") {
			t.Fatal("I/O 边界泄露地址或丢失原因", err)
		}
	}
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

type failHandshakeWriteConn struct {
	net.Conn
	armed atomic.Bool
	cause error
}

func (c *failHandshakeWriteConn) Write(p []byte) (int, error) {
	if c.armed.Load() {
		return 0, c.cause
	}
	return c.Conn.Write(p)
}

func TestHandshakeWriteErrorRedactsAddressesAndKeepsCause(t *testing.T) {
	opts := stallOptions(t, time.Second)
	originalDial := opts.Dial
	cause := &net.OpError{Op: "write", Net: "tcp", Source: &net.TCPAddr{IP: net.ParseIP("192.0.2.11"), Port: 1234}, Addr: &net.TCPAddr{IP: net.ParseIP("198.51.100.10"), Port: 441}, Err: io.ErrClosedPipe}
	var raw *failHandshakeWriteConn
	opts.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := originalDial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		raw = &failHandshakeWriteConn{Conn: conn, cause: cause}
		return raw, nil
	}
	conn, err := dialNodeTLS(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	raw.armed.Store(true)
	_, err = handshakeTunnel(t.Context(), opts, conn)
	if !errors.Is(err, io.ErrClosedPipe) || strings.Contains(err.Error(), "192.0.2.11") || strings.Contains(err.Error(), "198.51.100.10") {
		t.Fatal("握手写错误泄露地址或丢失原因", err)
	}
}

func TestHandshakeSessionGoneOverridesStatus(t *testing.T) {
	for _, status := range []byte{0, 0x86} {
		frame := append([]byte{5, 0xd0, 0x53, status, 0, 17}, []byte(`{"code":75500002}`)...)
		_, err := readHandshake(bufio.NewReader(bytes.NewReader(frame)))
		var gone *ErrSessionGone
		if !errors.As(err, &gone) {
			t.Fatal("SID 失效被局部状态覆盖", err)
		}
	}
}

func TestSessionGoneAuthClosesBeforeHashValidation(t *testing.T) {
	for _, body := range []string{`{"code":75500002}`, `{"code":75500002,"data":{"conntrackHash":1}}`} {
		ft, _, _ := pendingAuthFixture(t, time.Now)
		local, remote := net.Pipe()
		defer remote.Close()
		conn := &tunnelConn{flows: ft, conn: local, raw: local, closeCh: make(chan struct{}), logf: func(string, ...any) {}}
		conn.handleAuthResp(authRetryStatus, []byte(body))
		select {
		case <-conn.Done():
		default:
			t.Fatal("SID 失效后连接仍存活")
		}
		var gone *ErrSessionGone
		if !errors.As(conn.Err(), &gone) {
			t.Fatal("会话失效未分类", conn.Err())
		}
		_ = conn.Close()
	}
}
