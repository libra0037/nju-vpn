package ztna

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
	"testing"
)

// 这些用例把握手信封、数据帧、鉴权帧的形状逐字节钉死。它们对应的是服务端
// 的线上契约：改一处常量就该有一处用例跟着变红。

func TestHandshakeRequestBytes(t *testing.T) {
	got := handshakeRequest("abc")
	payload := []byte(`{"sid":"abc"}`)
	want := []byte{0x05, 0x01, 0xD0, 0x53, 0x00, 0x00, byte(len(payload))}
	want = append(want, payload...)
	want = append(want, 0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0)
	if !bytes.Equal(got, want) {
		t.Fatalf("握手请求 = %s，期望 %s", hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

func TestHandshakeRequestLengthTracksPayload(t *testing.T) {
	short := handshakeRequest("a")
	long := handshakeRequest(strings.Repeat("x", 300))
	if short[5] != 0 || short[6] != 11 {
		t.Errorf("短 sid 的长度字段 = %d,%d，期望 0,9", short[5], short[6])
	}
	if n := int(binary.BigEndian.Uint16(long[5:7])); n != 300+10 {
		t.Errorf("长 sid 的长度字段 = %d，期望 %d", n, 300+9)
	}
}

func TestHandshakeResponseParsing(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0x05, 0xD0})
	// 先来一个信封（服务端会这样回），再来真正的地址。
	envelope := []byte(`{"code":0}`)
	buf.Write([]byte{0x53, 0x00})
	_ = binary.Write(&buf, binary.BigEndian, uint16(len(envelope)))
	buf.Write(envelope)
	buf.Write([]byte{0x05, 0x00, 0x00, 0x01, 172, 16, 0, 9, 0, 0})

	res, err := readHandshake(bufio.NewReader(&buf))
	if err != nil {
		t.Fatalf("读握手响应失败: %v", err)
	}
	if got := res.VIP.String(); got != "172.16.0.9" {
		t.Errorf("分配的地址 = %s，期望 172.16.0.9", got)
	}
}

func TestHandshakeRejectsEnvelopeErrorCode(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0x05, 0xD0})
	// 状态字节是 0，但信封里的 code 非 0——会话失效时服务端就是这么回的。
	envelope := []byte(`{"code":75500006,"message":"already online"}`)
	buf.Write([]byte{0x53, 0x00})
	_ = binary.Write(&buf, binary.BigEndian, uint16(len(envelope)))
	buf.Write(envelope)

	_, err := readHandshake(bufio.NewReader(&buf))
	if err == nil {
		t.Fatal("code 非 0 的握手响应应被拒绝")
	}
	if !strings.Contains(err.Error(), "already online") {
		t.Errorf("错误信息里应带上服务端说明，得到 %v", err)
	}
}

func TestHandshakeRejectsBadMethod(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0x05, 0x01})
	if _, err := readHandshake(bufio.NewReader(&buf)); err == nil {
		t.Fatal("非预期的方法响应应被拒绝")
	}
}

func TestVIPBodyLengths(t *testing.T) {
	cases := []struct {
		atype byte
		want  int
	}{{1, 6}, {4, 18}, {5, 22}}
	for _, c := range cases {
		got, err := vipBodyLen(c.atype)
		if err != nil || got != c.want {
			t.Errorf("addrType %d 的体长 = %d（%v），期望 %d", c.atype, got, err, c.want)
		}
	}
	if _, err := vipBodyLen(9); err == nil {
		t.Error("未知的地址类型应报错")
	}
}

func TestParseVIP(t *testing.T) {
	body := []byte{10, 1, 2, 3, 0, 0}
	if got := parseVIP(1, body); got.String() != "10.1.2.3" {
		t.Errorf("地址 = %v，期望 10.1.2.3", got)
	}
	if got := parseVIP(4, body); got != nil {
		t.Errorf("非 IPv4 的地址类型应返回 nil，得到 %v", got)
	}
}

func TestDataFrameBytes(t *testing.T) {
	pkt := ipv4TCP("10.0.0.1", "10.1.2.3", 1234, 80, nil)
	frame, err := encodeDataFrame("tok", pkt)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x05, 0x14, 0x03, 't', 'o', 'k', 0x00, 0x00, 0x01}
	want = binary.BigEndian.AppendUint16(want, uint16(len(pkt)))
	want = append(want, pkt...)
	if !bytes.Equal(frame, want) {
		t.Errorf("数据帧 = %s，期望 %s", hex.EncodeToString(frame), hex.EncodeToString(want))
	}
}

func TestDataFrameRejectsEmptyPacket(t *testing.T) {
	if _, err := encodeDataFrame("tok", nil); err == nil {
		t.Error("空包应被拒绝")
	}
}

func TestAuthRequestFrameBytes(t *testing.T) {
	frame, err := encodeAuthRequest([]byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x05, 0x13, 0x00, 0x02, '{', '}'}
	if !bytes.Equal(frame, want) {
		t.Errorf("鉴权帧 = %s，期望 %s", hex.EncodeToString(frame), hex.EncodeToString(want))
	}
}

func TestHeartbeatFrameBytes(t *testing.T) {
	want := []byte{0x05, 0x15, 0x00, 0x00}
	if !bytes.Equal(encodeHeartbeat(), want) {
		t.Errorf("心跳帧 = %s，期望 %s", hex.EncodeToString(encodeHeartbeat()), hex.EncodeToString(want))
	}
}

func TestReadFrameRejectsUnknownCommand(t *testing.T) {
	buf := bytes.NewReader([]byte{0x05, 0x77})
	if _, err := readFrame(bufio.NewReader(buf)); err == nil {
		t.Error("未知帧应被拒绝")
	}
}

func TestSplitPacketsHandlesConcatenationAndPartial(t *testing.T) {
	a := ipv4TCP("10.0.0.1", "10.1.2.3", 1, 2, []byte("aaa"))
	b := ipv4TCP("10.0.0.1", "10.1.2.3", 3, 4, []byte("bb"))
	stream := append(append([]byte(nil), a...), b...)
	stream = append(stream, b[:10]...) // 第三个包只到了一半

	pkts, rest, err := splitPackets(stream)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkts) != 2 {
		t.Fatalf("切出 %d 个包，期望 2", len(pkts))
	}
	if !bytes.Equal(pkts[0], a) || !bytes.Equal(pkts[1], b) {
		t.Error("切出来的包内容不对")
	}
	if len(rest) != 10 {
		t.Errorf("剩下 %d 字节，期望 10", len(rest))
	}
}

func TestSplitPacketsRejectsNonIPv4(t *testing.T) {
	if _, _, err := splitPackets([]byte{0x60, 0, 0, 0}); err == nil {
		t.Error("非 IPv4 数据应被拒绝")
	}
}

func TestParsePacketExtractsFiveTuple(t *testing.T) {
	pkt := ipv4TCP("10.0.0.1", "10.1.2.3", 1234, 443, nil)
	info, err := parsePacket(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if info.key.src != "10.0.0.1" || info.key.dst != "10.1.2.3" {
		t.Errorf("五元组地址 = %s -> %s", info.key.src, info.key.dst)
	}
	if info.key.sport != 1234 || info.key.dport != 443 {
		t.Errorf("五元组端口 = %d -> %d", info.key.sport, info.key.dport)
	}
	if protoName(info.proto) != "tcp" {
		t.Errorf("协议 = %s，期望 tcp", protoName(info.proto))
	}
}

func TestParsePacketRejectsBadInput(t *testing.T) {
	cases := map[string][]byte{
		"过短":     {0x45, 0x00},
		"非 IPv4": append([]byte{0x60}, make([]byte, 19)...),
		"总长超限": func() []byte {
			p := ipv4TCP("10.0.0.1", "10.1.2.3", 1, 2, nil)
			binary.BigEndian.PutUint16(p[2:], 9999)
			return p
		}(),
		"不支持的协议": func() []byte { p := ipv4TCP("10.0.0.1", "10.1.2.3", 1, 2, nil); p[9] = 47; return p }(),
	}
	for name, pkt := range cases {
		if _, err := parsePacket(pkt); err == nil {
			t.Errorf("%s: 应被拒绝", name)
		}
	}
}

func TestParseIPRangeAndPortRange(t *testing.T) {
	lo, hi, ok := parseIPRange("10.0.0.0/24")
	if !ok || lo != binary.BigEndian.Uint32(net.ParseIP("10.0.0.0").To4()) || hi != binary.BigEndian.Uint32(net.ParseIP("10.0.0.255").To4()) {
		t.Errorf("CIDR 解析结果 = %d-%d（%v）", lo, hi, ok)
	}
	lo, hi, ok = parseIPRange("10.0.0.1-10.0.0.5")
	if !ok || hi-lo != 4 {
		t.Errorf("区间解析结果 = %d-%d（%v）", lo, hi, ok)
	}
	lo, hi, ok = parseIPRange("10.0.0.7")
	if !ok || lo != hi {
		t.Errorf("单地址解析结果 = %d-%d（%v）", lo, hi, ok)
	}
	if _, _, ok := parseIPRange("example.com"); ok {
		t.Error("域名不该被当成可匹配的资源")
	}

	if a, b := parsePortRange(""); a != 1 || b != 65535 {
		t.Errorf("空端口 = %d-%d，期望全放行", a, b)
	}
	if a, b := parsePortRange("443"); a != 443 || b != 443 {
		t.Errorf("单端口 = %d-%d", a, b)
	}
	if a, b := parsePortRange("8000-8100"); a != 8000 || b != 8100 {
		t.Errorf("端口段 = %d-%d", a, b)
	}
}

func TestResourceTableMatchAndNodes(t *testing.T) {
	raw := []byte(`{"code":0,"data":{"appList":{"data":{"appInfo":[{"apps":[
		{"id":"app-a","nodeGroupId":"groupWan","accessModel":"L3VPN","addressList":[
			{"protocol":"tcp","port":"443","host":"10.1.0.0/16"},
			{"protocol":"all","port":"0","host":"172.16.0.1-172.16.0.9"}]},
		{"id":"app-b","nodeGroupId":"groupWan","accessModel":"Web","addressList":[
			{"protocol":"all","port":"0","host":"10.2.0.0/16"}]}
		]}],"config":{"nodeGroupConf":{"majorNodeGroup":{"id":"groupWan"},"nodeGroupList":[
		{"id":"groupWan","addressInfo":[{"address":"node-a:441","type":"wan"}]},
		{"id":"groupLan","addressInfo":[{"address":"node-b:441","type":"lan"}]}]}}}},
		"sdpPolicy":{"data":{"clientOption":{"dnsOption":{"firstDNS":"10.0.0.53"}}}}}}`)

	table, err := parseResourceTable(raw, "vpn.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(table.entries) != 2 {
		t.Fatalf("资源条数 = %d，期望 2（Web 资源不参与 L3 匹配）", len(table.entries))
	}

	cases := []struct {
		name  string
		dst   string
		proto string
		port  uint16
		ok    bool
	}{
		{"命中 TCP 资源", "10.1.2.3", "tcp", 443, true},
		{"端口不在范围内", "10.1.2.3", "tcp", 80, false},
		{"协议不匹配", "10.1.2.3", "udp", 443, false},
		{"命中 all 区间", "172.16.0.5", "udp", 53, true},
		{"区间之外", "172.16.0.10", "udp", 53, false},
		{"表外地址", "8.8.8.8", "tcp", 53, false},
	}
	for _, c := range cases {
		dst := net.ParseIP(c.dst)
		appID, _, ok := table.match(dst, c.proto, c.port)
		if ok != c.ok {
			t.Errorf("%s: 匹配 = %v，期望 %v", c.name, ok, c.ok)
		}
		if ok && appID == "" {
			t.Errorf("%s: 命中却没有 appID", c.name)
		}
	}

	nodes := table.candidateNodes("groupLan")
	if len(nodes) != 2 || nodes[0] != "node-b:441" {
		t.Errorf("优先组没排在前面: %v", nodes)
	}
	if got := table.candidateNodes(""); len(got) != 2 || got[0] != "node-a:441" {
		t.Errorf("没有优先组时应退到主节点组: %v", got)
	}
}

func TestParseResourceTableSubstitutesHostPlaceholder(t *testing.T) {
	raw := []byte(`{"data":{"appList":{"data":{"config":{"nodeGroupConf":{"majorNodeGroup":{"id":"g"},
		"nodeGroupList":[{"id":"g","addressInfo":[{"address":"{{sdpcHost}}","type":"wan"}]}]}}}}}}`)
	table, err := parseResourceTable(raw, "vpn.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(table.nodes) != 1 || table.nodes[0].addr != "vpn.test:441" {
		t.Errorf("节点地址 = %v，期望 vpn.test:441", table.nodes)
	}
}

// ipv4TCP 造一个最小的 IPv4 + TCP 包。协议层不校验传输层校验和，因此这里
// 不填：要验的是解析与匹配，不是校验和算法。
func ipv4TCP(src, dst string, sport, dport uint16, payload []byte) []byte {
	total := 20 + 20 + len(payload)
	pkt := make([]byte, total)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(total))
	pkt[8] = 64
	pkt[9] = protoTCP
	copy(pkt[12:16], net.ParseIP(src).To4())
	copy(pkt[16:20], net.ParseIP(dst).To4())
	binary.BigEndian.PutUint16(pkt[20:], sport)
	binary.BigEndian.PutUint16(pkt[22:], dport)
	binary.BigEndian.PutUint16(pkt[24:], uint16(total-20))
	pkt[32] = 0x50
	copy(pkt[40:], payload)
	return pkt
}
