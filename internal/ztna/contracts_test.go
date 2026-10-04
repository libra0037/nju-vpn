package ztna

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestCryptoInputsHaveCPUAndLengthBudgets(t *testing.T) {
	for _, p := range [][2]string{{strings.Repeat("f", 2049), "65537"}, {"ff", "2"}, {"ff", "2147483648"}} {
		if _, err := parseRSAPublicKey(p[0], p[1]); err == nil {
			t.Fatal("超预算或非法公钥被接受")
		}
	}
	if _, err := encryptPassword(&rsa.PublicKey{N: big.NewInt(255), E: 65537}, strings.Repeat("p", 8193)); err == nil {
		t.Fatal("加密输入预算未限制")
	}
	if _, err := New(Options{NodeSPKIPins: [][32]byte{{1}}}); err == nil {
		t.Fatal("构造未拒绝缺失依赖")
	}
	fn := func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("构造时不得拨号")
		return nil, nil
	}
	if _, err := New(Options{Server: "vpn.test", DialAddr: "vpn.test:443", Dial: fn, DeviceID: "device", NodeSPKIPins: [][32]byte{{1}}, MTU: 1400}); err != nil {
		t.Fatal(err)
	}
}

func TestEncodedResourceBudgetIncludesEscaping(t *testing.T) {
	resources := L3Resources{
		IP:        []IPv4Resource{{ID: "<>\\\n\x1b", NodeGroupID: "g", Host: netip.MustParsePrefix("192.0.2.1/32"), Protocol: ResourceProtocolTCP, Port: [2]uint16{443, 443}}},
		NodeGroup: map[string][]ResourceNode{"g": {{Address: "node.test:441", Type: "wan"}}},
	}
	table := &resourceTable{L3Resources: resources}
	const want = `{"ip":[{"id":"\u003c\u003e\\\n\u001b","nodeGroupId":"g","protocol":6,"host":"192.0.2.1/32","port":[443,443]}],"dns":{"firstDNS":"","secondDNS":""},"nodegroup":{"g":[{"address":"node.test:441","type":"wan"}]}}`
	got, err := table.snapshotJSON(len(want))
	if err != nil || !bytes.Equal(got, []byte(want)) {
		t.Fatal("恰好达到预算的完整 JSON 被拒绝", string(got), err)
	}
	if got, err := table.snapshotJSON(len(want) - 1); !errors.Is(err, ErrResourceSnapshotTooLarge) || got != nil {
		t.Fatal("超限仍有部分响应", got, err)
	}
}
func TestHandshakeSIDChecksEncodedLength(t *testing.T) {
	if _, err := handshakeRequest(""); err == nil {
		t.Fatal("空 SID 被接受")
	}
	if _, err := handshakeRequest(strings.Repeat("\n", 32763)); err == nil {
		t.Fatal("JSON 转义后 SID 越过 65535")
	}
	if req, err := handshakeRequest(strings.Repeat("\n", 32762) + "a"); err != nil || binary.BigEndian.Uint16(req[5:7]) != 65535 {
		t.Fatal("恰好 65535 字节的 SID 编码被拒绝", err)
	}
	req, err := handshakeRequest(strings.Repeat("a", 1000))
	if err != nil {
		t.Fatal(err)
	}
	// 固定线上结构：05 01 d0 53 00 + 双字节长度 + JSON，后面另有地址请求。
	if !bytes.Equal(req[:4], []byte{5, 1, 0xd0, 0x53}) {
		t.Fatal("握手前缀改变")
	}
	n := int(binary.BigEndian.Uint16(req[5:7]))
	var value map[string]string
	if err := json.Unmarshal(req[7:7+n], &value); err != nil || value["sid"] != strings.Repeat("a", 1000) {
		t.Fatal("SID 编码长度被截断", n, err)
	}
}
func TestAuthenticationResponsesRejectMissingRequiredFields(t *testing.T) {
	bad := []string{
		`{"data":{"conntrackHash":1,"connectToken":"t"}}`,
		`{"code":null,"data":{"conntrackHash":1,"connectToken":"t"}}`,
		`{"code":0,"data":{"connectToken":"t"}}`,
		`{"code":0,"data":{"conntrackHash":null,"connectToken":"t"}}`,
		`{"code":0,"data":{"conntrackHash":1,"connectToken":""}}`,
		`{"code":0,"data":{"conntrackHash":1,"connectToken":"` + strings.Repeat("t", 256) + `"}}`,
	}
	for _, body := range bad {
		a, b := net.Pipe()
		tc := &tunnelConn{conn: a, raw: a, flows: newFlowTable(), closeCh: make(chan struct{}), logf: func(string, ...any) {}}
		tc.handleAuthResp(0, []byte(body))
		select {
		case <-tc.Done():
		case <-time.After(time.Second):
			t.Fatal("非法响应未关闭连接")
		}
		if tc.Err() == nil {
			t.Fatal("缺少可诊断的协议错误")
		}
		b.Close()
	}
}
func TestDataFrameReadyTokenBoundaries(t *testing.T) {
	for _, n := range []int{0, 256} {
		if _, err := encodeDataFrame(strings.Repeat("t", n), []byte{1}); err == nil {
			t.Fatal("非法 token 长度被接受", n)
		}
	}
	if _, err := encodeDataFrame(strings.Repeat("t", 255), []byte{1}); err != nil {
		t.Fatal("有效 token 被拒绝", err)
	}
}
func TestMalformedTailClearsExistingAssociation(t *testing.T) {
	ft := newFlowTable()
	queueFragment(t, ft, udpFragment(1, 0, true, 16))
	tail := udpFragment(1, 2, false, 16)
	tail = tail[:len(tail)-1]
	tc := &tunnelConn{flows: ft}
	if err := tc.Send(tail); err == nil {
		t.Fatal("长度错误的尾片被接受")
	}
	if len(ft.fragments) != 0 {
		t.Fatal("可确定键的错误尾片仍保留关联")
	}
}
func BenchmarkResourceMatch(b *testing.B) {
	for _, n := range []int{256, 16384} {
		b.Run(stringSize(n), func(b *testing.B) {
			rules := make([]IPv4Resource, n)
			for i := range rules {
				rules[i] = IPv4Resource{Host: netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), 32), Protocol: ResourceProtocolAll, Port: [2]uint16{1, 65535}, ID: "a"}
			}
			table := &resourceTable{L3Resources: L3Resources{IP: rules}}
			dst := netip.MustParseAddr("255.255.255.254")
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				table.match(dst, protoTCP, 443)
			}
		})
	}
}
func stringSize(n int) string {
	if n == 256 {
		return "normal-256"
	}
	return "limit-16384"
}
func BenchmarkEncodeMaximumPacket(b *testing.B) {
	pkt := make([]byte, 1400)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := encodeDataFrame("ready-token", pkt); err != nil {
			b.Fatal(err)
		}
	}
}
