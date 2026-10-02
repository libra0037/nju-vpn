package wireguard

import "testing"

func BenchmarkAddressMappingMaximumPacket(b *testing.B) {
	peer, public := [4]byte{10, 66, 66, 2}, [4]byte{172, 16, 0, 9}
	mapper, err := NewDynamicMapper(peer[:], func() ([4]byte, bool) { return public, true })
	if err != nil {
		b.Fatal(err)
	}
	pkt := buildUDP(peer, public, make([]byte, 1372))
	head := append([]byte(nil), pkt[:28]...)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(pkt[:28], head) // 每轮恢复固定头部，保持校验和合法。
		if _, err := mapper.Uplink(pkt); err != nil {
			b.Fatal(err)
		}
	}
}
