package service

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	wg "github.com/libra0037/nju-vpn/internal/wireguard"
	"github.com/libra0037/nju-vpn/internal/ztnatest"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type stopTestTun struct {
	q      chan []byte
	events chan tun.Event
	closed chan struct{}
	once   sync.Once
}

func (t *stopTestTun) File() *os.File           { return nil }
func (t *stopTestTun) Name() (string, error)    { return "stop-test", nil }
func (t *stopTestTun) MTU() (int, error)        { return 1400, nil }
func (t *stopTestTun) BatchSize() int           { return 1 }
func (t *stopTestTun) Events() <-chan tun.Event { return t.events }
func (t *stopTestTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case p := <-t.q:
		sizes[0] = copy(bufs[0][offset:], p)
		return 1, nil
	case <-t.closed:
		return 0, os.ErrClosed
	}
}
func (t *stopTestTun) Write(bufs [][]byte, _ int) (int, error) { return len(bufs), nil }
func (t *stopTestTun) Close() error {
	t.once.Do(func() { close(t.closed); close(t.events) })
	return nil
}

type writeGate struct {
	net.Conn
	target          *atomic.Pointer[writeGate]
	entered, closed chan struct{}
	once, closeOnce sync.Once
}

func (c *writeGate) Write(p []byte) (int, error) {
	if c.target.Load() == c {
		c.once.Do(func() { close(c.entered) })
		<-c.closed
		return 0, net.ErrClosed
	}
	return c.Conn.Write(p)
}
func (c *writeGate) Close() error { c.closeOnce.Do(func() { close(c.closed) }); return c.Conn.Close() }

func TestStopInterruptsBlockedWireGuardUplinkBeforeRemovingPeer(t *testing.T) {
	srv := newFakeServer(t, ztnatest.Options{})
	cfg := newTestConfig(t, srv)
	peerKey, err := wg.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	peerPub, _ := peerKey.PublicKey()
	cfg.WireGuard.PeerPublicKey = peerPub.String()
	var target atomic.Pointer[writeGate]
	var mu sync.Mutex
	var latest *writeGate
	fn := func(ctx context.Context, network, address string) (net.Conn, error) {
		raw, err := srv.Dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		c := &writeGate{Conn: raw, target: &target, entered: make(chan struct{}), closed: make(chan struct{})}
		mu.Lock()
		latest = c
		mu.Unlock()
		return c, nil
	}
	svc := newTestService(t, srv, cfg, Options{Dial: fn})
	if err := svc.Start(false, ""); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	dataConn := latest
	mu.Unlock()
	port, err := svc.br.dev.ListenPort()
	if err != nil {
		t.Fatal(err)
	}
	private, _ := wg.ParseKey(cfg.WireGuard.PrivateKey)
	public, _ := private.PublicKey()
	memory := &stopTestTun{q: make(chan []byte, 2), events: make(chan tun.Event, 1), closed: make(chan struct{})}
	memory.events <- tun.EventUp
	peer := device.NewDevice(memory, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(peer.Close)
	uapi := fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=0.0.0.0/0\n", hex.EncodeToString(peerKey[:]), hex.EncodeToString(public[:]), port)
	if err := peer.IpcSet(uapi); err != nil {
		t.Fatal(err)
	}
	if err := peer.Up(); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 40)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], 40)
	packet[8] = 64
	packet[9] = 6
	copy(packet[12:20], []byte{10, 66, 66, 2, 10, 1, 2, 3})
	copy(packet[20:24], []byte{0x9c, 0x40, 0x01, 0xbb})
	packet[32] = 0x50
	memory.q <- packet
	deadline := time.After(3 * time.Second)
	for len(srv.Uplink()) == 0 {
		select {
		case <-deadline:
			t.Fatal("首包未完成鉴权和发送")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	target.Store(dataConn)
	memory.q <- packet
	select {
	case <-dataConn.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("WireGuard 同步上行未进入写屏障")
	}
	done := make(chan error, 1)
	go func() { done <- svc.Stop() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		dataConn.Close()
		t.Fatal("Stop 在关闭连接之前等待 peer")
	}
	if svc.Status().State != StateIdle || srv.LogoutCount() != 1 {
		t.Fatal("停止未收敛或未尝试登出", svc.Status(), srv.LogoutCount())
	}
	svc.Close()
}
