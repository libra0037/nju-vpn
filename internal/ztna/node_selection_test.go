package ztna

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/ztnatest"
)

// 固定交错：第一个节点接受 TCP 后关闭 TLS；第二个节点必须等到前者的
// ClientHello 才可达。旧实现先选第一个 TCP 成功，随后 TLS 失败就结束登录。
func TestConnectSkipsNodeThatClosesBeforeTLS(t *testing.T) {
	const badNode, goodNode = "closed.test:441", "ready.test:441"
	srv := newFake(t, ztnatest.Options{Nodes: []string{badNode, goodNode}})
	client := newTestClient(t, srv, testPass)
	hello := make(chan struct{})
	var helloOnce sync.Once
	var workers sync.WaitGroup
	var badDials, goodDials atomic.Int32
	var mu sync.Mutex
	var pipes []net.Conn
	t.Cleanup(func() {
		mu.Lock()
		for _, c := range pipes {
			c.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	client.opts.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		switch address {
		case badNode:
			badDials.Add(1)
			a, b := net.Pipe()
			mu.Lock()
			pipes = append(pipes, a, b)
			mu.Unlock()
			workers.Go(func() {
				defer b.Close()
				var buf [4096]byte
				if n, _ := b.Read(buf[:]); n > 0 && buf[0] == 0x16 {
					helloOnce.Do(func() { close(hello) })
				}
			})
			return a, nil
		case goodNode:
			select {
			case <-hello:
				goodDials.Add(1)
				return srv.Dial(ctx, network, srv.Addr())
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		default:
			return srv.Dial(ctx, network, address)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	sess, err := client.Connect(ctx, ConnectOptions{})
	if sess != nil {
		defer sess.Close(context.Background())
	}
	if err != nil {
		t.Fatal("TCP 连通但 TLS 关闭的节点阻止了登录", err)
	}
	if sess.node != goodNode || badDials.Load() != 1 || goodDials.Load() != 1 {
		t.Fatal("未选中并复用已验证的 TLS 连接", sess.node, badDials.Load(), goodDials.Load())
	}
	if srv.Tunnels() != 1 {
		t.Fatal("选节点建立了额外的协议隧道", srv.Tunnels())
	}
}

type nodeCloseSpy struct {
	net.Conn
	closed atomic.Bool
	once   sync.Once
	after  func()
}

func (c *nodeCloseSpy) Close() error {
	c.closed.Store(true)
	err := c.Conn.Close()
	if c.after != nil {
		c.once.Do(c.after)
	}
	return err
}

func TestConnectSkipsNodeWithUnconfiguredSPKI(t *testing.T) {
	const badNode, goodNode = "untrusted.test:441", "trusted.test:441"
	bad := newFake(t, ztnatest.Options{})
	good := newFake(t, ztnatest.Options{Nodes: []string{badNode, goodNode}})
	client := newTestClient(t, good, testPass)
	rejected := make(chan struct{})
	client.opts.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		switch address {
		case badNode:
			c, err := bad.Dial(ctx, network, bad.Addr())
			if err != nil {
				return nil, err
			}
			return &nodeCloseSpy{Conn: c, after: func() { close(rejected) }}, nil
		case goodNode:
			select {
			case <-rejected:
				return good.Dial(ctx, network, good.Addr())
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		default:
			return good.Dial(ctx, network, address)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	sess, err := client.Connect(ctx, ConnectOptions{})
	if sess != nil {
		defer sess.Close(context.Background())
	}
	if err != nil || sess.node != goodNode {
		t.Fatal("未跳过指纹不在配置中的节点", err)
	}
	if bad.Tunnels() != 0 || good.Tunnels() != 1 {
		t.Fatal("未验证的节点收到协议握手，或重复建立隧道", bad.Tunnels(), good.Tunnels())
	}
}

func verifiedProbeFixture(t *testing.T, srv *ztnatest.Server) (*tls.Conn, *nodeCloseSpy) {
	t.Helper()
	raw, err := srv.Dial(t.Context(), "tcp", srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	spy := &nodeCloseSpy{Conn: raw}
	t.Cleanup(func() { spy.Close() })
	conn, err := dialNodeTLS(t.Context(), tunnelOptions{
		Node: srv.Addr(), Server: "vpn.test", Pins: newNodeSPKIPins([][32]byte{srv.SPKIPin()}),
		Dial: func(context.Context, string, string) (net.Conn, error) { return spy, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return conn, spy
}

func TestProbeTransfersWinnerAndClosesUnselectedConnections(t *testing.T) {
	srv := newFake(t, ztnatest.Options{})
	addrs := []string{"node-1:441", "node-2:441", "node-3:441"}
	connections := make(map[string]*tls.Conn)
	var spies []*nodeCloseSpy
	for _, addr := range addrs {
		conn, spy := verifiedProbeFixture(t, srv)
		connections[addr] = conn
		spies = append(spies, spy)
	}
	entered := make(chan struct{}, len(addrs))
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseAll)
	done := make(chan struct{})
	var winner *tls.Conn
	var err error
	go func() {
		defer close(done)
		_, winner, err = probeNodes(t.Context(), func(_ context.Context, addr string) (*tls.Conn, error) {
			entered <- struct{}{}
			<-release
			return connections[addr], nil
		}, addrs, time.Second)
	}()
	for range addrs {
		awaitSignal(t, entered)
	}
	releaseAll()
	awaitSignal(t, done)
	if err != nil || winner == nil {
		t.Fatal("没有接纳成功连接", err)
	}
	for i, addr := range addrs {
		if spies[i].closed.Load() != (connections[addr] != winner) {
			t.Fatal("连接所有权不正确", i, spies[i].closed.Load())
		}
	}
}

func TestProbeCancellationClosesLateConnectionAndJoinsWorker(t *testing.T) {
	srv := newFake(t, ztnatest.Options{})
	conn, spy := verifiedProbeFixture(t, srv)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseWorker := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseWorker)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var winner *tls.Conn
	var err error
	go func() {
		defer close(done)
		_, winner, err = probeNodes(ctx, func(context.Context, string) (*tls.Conn, error) {
			close(entered)
			<-release
			return conn, nil
		}, []string{srv.Addr()}, time.Second)
	}()
	awaitSignal(t, entered)
	cancel()
	select {
	case <-done:
		releaseWorker()
		t.Fatal("取消后未等待工作者交出连接")
	case <-time.After(30 * time.Millisecond):
	}
	releaseWorker()
	awaitSignal(t, done)
	if !errors.Is(err, context.Canceled) || winner != nil || !spy.closed.Load() {
		t.Fatal("取消后接纳或泄漏迟到连接", err, winner, spy.closed.Load())
	}
}
