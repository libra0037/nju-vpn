package wireguard

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"njuvpn/internal/vpn"
)

// ipv4Pkt 造一个长度合法的 IPv4 包（最小头部 + 指定大小的载荷）。
func ipv4Pkt(src, dst [4]byte, payload int) []byte {
	pkt := make([]byte, 20+payload)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	pkt[9] = 17 // UDP
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	for i := 20; i < len(pkt); i++ {
		pkt[i] = byte(i)
	}
	return pkt
}

func newTestRelay(t *testing.T) (*Relay, *vpn.TunnelEndpoint) {
	t.Helper()
	ep := vpn.NewEndpoint()
	r := NewRelay(RelayOptions{MTU: 1320, Endpoint: ep})
	t.Cleanup(func() { r.Close() })
	return r, ep
}

// readOne 从 relay 读一个包。
func readOne(t *testing.T, r *Relay, size int) []byte {
	t.Helper()
	bufs := [][]byte{make([]byte, size)}
	sizes := []int{0}
	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := r.Read(bufs, sizes, 0)
		done <- result{n: n, err: err}
	}()

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("Read 失败: %v", got.err)
		}
		if got.n != 1 {
			t.Fatalf("Read 返回 %d 个包，期望 1", got.n)
		}
		return bufs[0][:sizes[0]]
	case <-time.After(2 * time.Second):
		t.Fatal("等待下行包超时")
		return nil
	}
}

// 回归：隧道下行是字节流，服务端可能把两个包写进一次 TLS 记录。
// 旧实现把一次读到的字节当成一个包，粘包会直接产生非法报文。
func TestRelayFramesCoalescedPackets(t *testing.T) {
	r, ep := newTestRelay(t)
	peer := [4]byte{10, 66, 66, 2}
	pub := [4]byte{172, 29, 56, 18}

	first := ipv4Pkt(pub, peer, 100)
	second := ipv4Pkt(pub, peer, 200)

	// 两个包一次送达。
	coalesced := append(append([]byte(nil), first...), second...)
	ep.Deliver(coalesced)

	got1 := readOne(t, r, 1500)
	if len(got1) != len(first) {
		t.Fatalf("第一个包长度 = %d，期望 %d", len(got1), len(first))
	}
	got2 := readOne(t, r, 1500)
	if len(got2) != len(second) {
		t.Fatalf("第二个包长度 = %d，期望 %d", len(got2), len(second))
	}
}

// 回归：一个包分两次到达时，不能在第一个片段上就交给 WireGuard。
func TestRelayFramesSplitPacket(t *testing.T) {
	r, ep := newTestRelay(t)
	peer := [4]byte{10, 66, 66, 2}
	pub := [4]byte{172, 29, 56, 18}
	pkt := ipv4Pkt(pub, peer, 60)

	ep.Deliver(pkt[:30])
	ep.Deliver(pkt[30:])

	got := readOne(t, r, 1500)
	if len(got) != len(pkt) {
		t.Fatalf("包长度 = %d，期望 %d", len(got), len(pkt))
	}
	for i := range pkt {
		if got[i] != pkt[i] {
			t.Fatalf("第 %d 字节不一致", i)
		}
	}
}

// 不是 IPv4 的字节必须被丢掉，而不是原样交给 WireGuard。
func TestRelayDropsNonIPv4(t *testing.T) {
	r, ep := newTestRelay(t)
	ep.Deliver([]byte("this is not an ip packet at all, just text"))

	// 再送一个合法包，它必须能正常取出（说明前面的垃圾被清理了）。
	peer := [4]byte{10, 66, 66, 2}
	pub := [4]byte{172, 29, 56, 18}
	good := ipv4Pkt(pub, peer, 10)
	// 垃圾长度超过一个包，会先被当作一个"包"丢弃，这里手工补一帧。
	ep.Deliver(append(make([]byte, 0), good...))

	got := readOne(t, r, 1500)
	if len(got) != len(good) {
		t.Fatalf("粘在垃圾后面的合法包长度 = %d，期望 %d", len(got), len(good))
	}
}

// Close 之后 Read/Write 必须立即报错，而不是继续吐队列里的旧包。
func TestRelayClosedBehavior(t *testing.T) {
	r, ep := newTestRelay(t)
	peer := [4]byte{10, 66, 66, 2}
	pub := [4]byte{172, 29, 56, 18}
	ep.Deliver(ipv4Pkt(pub, peer, 10))

	if err := r.Close(); err != nil {
		t.Fatalf("Close 失败: %v", err)
	}

	bufs := [][]byte{make([]byte, 1500)}
	sizes := []int{0}
	if _, err := r.Read(bufs, sizes, 0); !errors.Is(err, ErrClosed) {
		t.Errorf("Close 后 Read 应返回 ErrClosed，实际 %v", err)
	}
	if _, err := r.Write([][]byte{ipv4Pkt(peer, pub, 10)}, 0); !errors.Is(err, ErrClosed) {
		t.Errorf("Close 后 Write 应返回 ErrClosed，实际 %v", err)
	}
}

// 上行没有通道时必须明确报错，让 WireGuard 知道数据没送出去。
func TestRelayWriteWithoutUplink(t *testing.T) {
	r, _ := newTestRelay(t)
	peer := [4]byte{10, 66, 66, 2}
	pub := [4]byte{172, 29, 56, 18}
	if _, err := r.Write([][]byte{ipv4Pkt(peer, pub, 10)}, 0); !errors.Is(err, vpn.ErrNoUplink) {
		t.Errorf("没有上行通道时应返回 ErrNoUplink，实际 %v", err)
	}
}

// 上行包必须经过地址改写：客户端用 peer 地址，隧道里必须用隧道地址。
func TestRelayAppliesMapperOnUplink(t *testing.T) {
	ep := vpn.NewEndpoint()
	mapper, err := NewMapper(net.ParseIP("10.66.66.2"), net.ParseIP("172.29.56.18"))
	if err != nil {
		t.Fatal(err)
	}
	r := NewRelay(RelayOptions{MTU: 1320, Endpoint: ep, Mapper: mapper})
	defer r.Close()

	var sent []byte
	ep.SetUplink(func(buf []byte) error {
		sent = append([]byte(nil), buf...)
		return nil
	})

	peer := [4]byte{10, 66, 66, 2}
	pub := [4]byte{172, 29, 56, 18}
	pkt := ipv4Pkt(peer, pub, 10)
	if _, err := r.Write([][]byte{pkt}, 0); err != nil {
		t.Fatalf("Write 失败: %v", err)
	}
	if sent == nil {
		t.Fatal("上行包没有被送出")
	}
	if [4]byte{sent[12], sent[13], sent[14], sent[15]} != pub {
		t.Errorf("上行源地址没有改写成隧道地址: %v", sent[12:16])
	}
}

// 下行包必须改回 peer 地址，否则客户端认不出这个包是自己的。
func TestRelayAppliesMapperOnDownlink(t *testing.T) {
	ep := vpn.NewEndpoint()
	mapper, err := NewMapper(net.ParseIP("10.66.66.2"), net.ParseIP("172.29.56.18"))
	if err != nil {
		t.Fatal(err)
	}
	r := NewRelay(RelayOptions{MTU: 1320, Endpoint: ep, Mapper: mapper})
	defer r.Close()

	peer := [4]byte{10, 66, 66, 2}
	pub := [4]byte{172, 29, 56, 18}
	// 下行包的目的地址必须正是隧道地址，才会被改写成 peer 地址。
	ep.Deliver(ipv4Pkt([4]byte{1, 1, 1, 1}, pub, 10))

	got := readOne(t, r, 1500)
	if [4]byte{got[16], got[17], got[18], got[19]} != peer {
		t.Errorf("下行目的地址没有改写成 peer 地址: %v", got[16:20])
	}
}

// 回归：缓冲区装不下的包必须丢掉，绝不能返回错误。
//
// wireguard-go 的 TUN 读协程收到非 ErrClosed 的错误会直接 go device.Close()，
// 一个超长包就能把整条承载层悄悄关掉（Windows 上缓冲区只有 2000 字节，
// 而隧道侧允许更大的包）。丢包由上层重传兜住，报错则会把承载层带走。
func TestRelayReadDropsOversizedPacket(t *testing.T) {
	r, ep := newTestRelay(t)
	peer := [4]byte{10, 66, 66, 2}
	pub := [4]byte{172, 29, 56, 18}

	// 先来一个装不下的，再来一个正常的：Read 必须跳过前者、交出后者。
	ep.Deliver(ipv4Pkt(pub, peer, 900))
	ep.Deliver(ipv4Pkt(pub, peer, 20))

	bufs := [][]byte{make([]byte, 60)}
	sizes := []int{0}
	n, err := r.Read(bufs, sizes, 0)
	if err != nil {
		t.Fatalf("装不下时应丢包而不是报错: %v", err)
	}
	if n != 1 || sizes[0] != 40 {
		t.Fatalf("应交出后面那个 40 字节的包（20 头部 + 20 载荷），得到 n=%d size=%d", n, sizes[0])
	}
	if r.dropped.Load() == 0 {
		t.Error("超长包应计入丢弃统计")
	}
}
