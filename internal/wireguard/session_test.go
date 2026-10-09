package wireguard

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/l3"
)

func TestSessionSwitchDuringMappingRejectsOldPacket(t *testing.T) {
	r := NewRelay(RelayOptions{MTU: 1400})
	defer r.Close()
	ep := l3.New()
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	mapper, err := NewDynamicMapper(net.IPv4(10, 66, 66, 2), func() ([4]byte, bool) {
		if calls.Add(1) == 2 {
			close(entered)
			<-release
		}
		return [4]byte{172, 16, 0, 9}, true
	})
	if err != nil {
		t.Fatal(err)
	}
	r.InstallSession(ep, mapper)
	done := make(chan struct{})
	go func() { defer close(done); ep.Deliver(ipv4Pkt([4]byte{10, 1, 2, 3}, [4]byte{172, 16, 0, 9}, 8)) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("未进入映射交错")
	}
	r.ClearSession()
	replacement := l3.New()
	r.InstallSession(replacement, nil)
	close(release)
	<-done
	if len(r.queue) != 0 {
		t.Fatal("排空后重新入队旧包")
	}
	oldOwner := &relaySession{ep: ep, mapper: mapper}
	stale := ipv4Pkt([4]byte{10, 1, 2, 3}, [4]byte{10, 66, 66, 2}, 8)
	r.queue <- queuedPacket{owner: oldOwner, data: stale}
	fresh := ipv4Pkt([4]byte{10, 1, 2, 4}, [4]byte{10, 66, 66, 2}, 8)
	replacement.Deliver(fresh)
	if got := readOne(t, r, 1400); !bytes.Equal(got, fresh) {
		t.Fatal("消费处未拒绝旧绑定包")
	}
}
func TestChangingUplinkErrorsCannotFloodOrExposeAddresses(t *testing.T) {
	var out bytes.Buffer
	old := log.Writer()
	log.SetOutput(&out)
	defer log.SetOutput(old)
	r := NewRelay(RelayOptions{MTU: 1400})
	defer r.Close()
	ep := l3.New()
	calls := 0
	ep.SetUplink(func([]byte) error {
		calls++
		return fmt.Errorf("secret-token 10.0.0.%d", calls)
	})
	r.InstallSession(ep, nil)
	packet := ipv4Pkt([4]byte{10, 66, 66, 2}, [4]byte{10, 1, 2, 3}, 20)
	for i := 0; i < 100; i++ {
		r.Write([][]byte{packet}, 0)
	}
	if calls != 100 || bytes.Count(out.Bytes(), []byte("\n")) != 1 || strings.Contains(out.String(), "secret-token") || strings.Contains(out.String(), "10.0.0.") {
		t.Fatal("丢包详情绕过限速或泄密", out.String())
	}
}
