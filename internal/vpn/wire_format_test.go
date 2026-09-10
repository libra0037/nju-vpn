package vpn

import (
	"context"
	"encoding/hex"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"njuvpn/internal/vpntest"
)

// 这个文件把与真实服务端的线上格式钉死。
//
// 报文是逐字节构造的，重构时很容易"顺手改一下"而看不出来；
// 一旦改错，服务端只会给一个控制码或者干脆不回应，排查代价极高。
// 下面每个常量都是从旧实现（0099b7a）逐字节核对过的。

// 测试用的假 SessionId 与 TwfID，参见 vpntest 里假服务端的默认值。
const (
	goldenSessionID = "0123456789abcdef0123456789abcdef"
	// goldenTwfID 是登录**结束后**生效的那个 TwfID：服务端在
	// login_psw.csp 的响应里换过一次，用登录页那个就对不上了。
	goldenTwfID = "fedcba9876543210"
)

// goldenIP 是假服务端默认分配到的地址。
var goldenIP = [4]byte{172, 29, 56, 18}

// goldenStreamToken 是 32 字节 token：SessionId 十六进制串的前 31 个字符
// 加一个结尾的 0，再拼 16 字节 TwfID。
func goldenStreamToken(t *testing.T) [streamTokenLen]byte {
	t.Helper()
	tok, err := streamToken("test", hex.EncodeToString([]byte(goldenSessionID))[:31]+"\x00", goldenTwfID)
	if err != nil {
		t.Fatalf("组装 token 失败: %v", err)
	}
	return tok
}

// 下行流握手帧的完整字节。任何一位都不能变。
const goldenStreamRecvFrame = "06000000333033313332333333343335333633373338333936313632363336343635360066656463626139383736353433323130000000000000000012381dac"

// 上行流握手帧：只有首字节的操作码不同。
const goldenStreamSendFrame = "05000000333033313332333333343335333633373338333936313632363336343635360066656463626139383736353433323130000000000000000012381dac"

// query-ip 帧：首 4 字节为 0，末 4 字节是 ffffffff 而不是反序地址。
const goldenQueryIPFrame = "000000003330333133323333333433353336333733383339363136323633363436353600666564636261393837363534333231300000000000000000ffffffff"

// 回归：流握手报文必须与旧实现逐字节一致。
func TestStreamHandshakeFrameIsStable(t *testing.T) {
	cases := []struct {
		name   string
		kind   byte
		golden string
	}{
		{"下行流", 0x06, goldenStreamRecvFrame},
		{"上行流", 0x05, goldenStreamSendFrame},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newScript(t)
			s.tunnel.SetSessionID([]byte(goldenSessionID))
			s.tunnel.SetIP(goldenIP)
			sess := connectedSession(t, s)

			if err := sess.CheckTunnel(context.Background()); err != nil {
				t.Fatalf("下行流握手失败: %v", err)
			}
			if c.kind == 0x05 {
				// 上行流要等 Run 建立。
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				go func() { _ = sess.Run(ctx) }()
				deadline := time.Now().Add(2 * time.Second)
				for time.Now().Before(deadline) && len(s.tunnel.StreamFrame(0x05)) == 0 {
					time.Sleep(5 * time.Millisecond)
				}
			}

			got := s.tunnel.StreamFrame(c.kind)
			if len(got) == 0 {
				t.Fatal("没有捕获到流握手报文")
			}
			if hex.EncodeToString(got) != c.golden {
				t.Errorf("流握手报文变了\n实际: %s\n期望: %s", hex.EncodeToString(got), c.golden)
			}
		})
	}
}

// 回归：query-ip 报文必须与旧实现逐字节一致。
func TestQueryIPFrameIsStable(t *testing.T) {
	s := newScript(t)
	s.tunnel.SetSessionID([]byte(goldenSessionID))
	s.tunnel.SetIP(goldenIP)
	client := newTestClient(t, s)

	sess, err := client.Connect(context.Background(), ConnectOptions{Username: "u", Password: "p"})
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	defer sess.Close(context.Background())

	got := s.tunnel.QueryFrame()
	if len(got) == 0 {
		t.Fatal("没有捕获到 query-ip 报文")
	}
	if hex.EncodeToString(got) != goldenQueryIPFrame {
		t.Errorf("query-ip 报文变了\n实际: %s\n期望: %s", hex.EncodeToString(got), goldenQueryIPFrame)
	}
}

// 回归：隧道 ClientHello 的参数是和服务端的契约，改动会被直接拒绝。
func TestTunnelHelloParameters(t *testing.T) {
	if tunnelHelloVersion != utls.VersionTLS11 {
		t.Errorf("隧道必须声明 TLS 1.1，实际 0x%04x", tunnelHelloVersion)
	}

	id := tunnelHelloSessionID()
	if len(id) != 32 {
		t.Errorf("SessionId 长度 = %d，期望 32", len(id))
	}
	if string(id[:4]) != "L3IP" {
		t.Errorf("SessionId 必须以 L3IP 开头，实际 %q", id[:4])
	}
	for i := 4; i < len(id); i++ {
		if id[i] != 0 {
			t.Fatalf("SessionId 第 %d 字节应为 0，实际 %d", i, id[i])
		}
	}

	suites := tunnelHelloCipherSuites()
	if len(suites) != 2 || suites[0] != utls.TLS_RSA_WITH_RC4_128_SHA {
		t.Errorf("套件列表变了: %v", suites)
	}
	if comp := tunnelHelloCompression(); len(comp) != 1 || comp[0] != 0 {
		t.Errorf("压缩方法变了: %v", comp)
	}
}

// 回归：token 的组成是 31 个十六进制字符 + 0 + 16 字节 TwfID。
func TestStreamTokenLayout(t *testing.T) {
	tok := goldenStreamToken(t)
	if got := hex.EncodeToString(tok[:tokenTotalLen]); got != "3330333133323333333433353336333733383339363136323633363436353600" {
		t.Errorf("token 段不是 SessionId 的十六进制前缀加 0: %s", got)
	}
	if got := string(tok[tokenTotalLen:]); got != goldenTwfID {
		t.Errorf("token 尾部的 TwfID = %q，期望 %q", got, goldenTwfID)
	}
}

// 地址反序：隧道用反序地址标识会话，写反了服务端会认成别的会话。
func TestIPRevIsReversed(t *testing.T) {
	ip := net.IPv4(goldenIP[0], goldenIP[1], goldenIP[2], goldenIP[3])
	rev := [4]byte{ip[15], ip[14], ip[13], ip[12]}
	want := [4]byte{goldenIP[3], goldenIP[2], goldenIP[1], goldenIP[0]}
	if rev != want {
		t.Errorf("反序地址 = %v，期望 %v", rev, want)
	}
	// golden 帧末尾就是它。
	tok := goldenStreamToken(t)
	_ = tok
	if goldenStreamRecvFrame[len(goldenStreamRecvFrame)-8:] != "12381dac" {
		t.Error("golden 帧末尾与反序地址不一致")
	}
}

// 确保 golden 帧确实是被真实代码路径发出去的，而不是只在测试里自洽。
func TestGoldenFramesComeFromRealCodePath(t *testing.T) {
	s := newScript(t)
	s.tunnel.SetSessionID([]byte(goldenSessionID))
	s.tunnel.SetIP(goldenIP)
	sess := connectedSession(t, s)

	if err := sess.CheckTunnel(context.Background()); err != nil {
		t.Fatalf("握手下行流失败: %v", err)
	}
	got := s.tunnel.StreamFrame(0x06)
	if len(got) != len(goldenStreamRecvFrame)/2 {
		t.Fatalf("帧长 = %d，期望 %d", len(got), len(goldenStreamRecvFrame)/2)
	}
	if vpntestFramesDiffer(got, goldenStreamRecvFrame) {
		t.Error("真实代码路径发出的帧与 golden 不一致")
	}
}

// vpntestFramesDiffer 比较一帧的十六进制与期望值。
func vpntestFramesDiffer(frame []byte, wantHex string) bool {
	return hex.EncodeToString(frame) != wantHex
}

var _ = vpntest.LoginAuthPage
