package ztna

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
)

// 这些用例把握手信封、数据帧、鉴权帧的形状逐字节钉死。它们对应的是服务端
// 的线上契约：改一处常量就该有一处用例跟着变红。

func TestHandshakeRequestBytes(t *testing.T) {
	got, err := handshakeRequest("abc")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"sid":"abc"}`)
	want := []byte{0x05, 0x01, 0xD0, 0x53, 0x00, 0x00, byte(len(payload))}
	want = append(want, payload...)
	want = append(want, 0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0)
	if !bytes.Equal(got, want) {
		t.Fatalf("握手请求 = %s，期望 %s", hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

func TestHandshakeRequestLengthTracksPayload(t *testing.T) {
	short, err := handshakeRequest("a")
	if err != nil {
		t.Fatal(err)
	}
	long, _ := handshakeRequest(strings.Repeat("x", 300))
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
	if !strings.Contains(err.Error(), "75500006") || strings.Contains(err.Error(), "already online") {
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

// TestHandshakeSessionGoneIsClassified 回归：握手信封里的会话失效码要翻成
// ErrSessionGone，而不是包成协议错误。
//
// 归错类会让调用方把它当通用失败重试三次，而不是直接提示"会话已失效，
// 请重新登录"。
func TestHandshakeSessionGoneIsClassified(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0x05, 0xD0})
	envelope := []byte(`{"code":75500002,"message":"sid expired"}`)
	buf.Write([]byte{0x53, 0x00})
	_ = binary.Write(&buf, binary.BigEndian, uint16(len(envelope)))
	buf.Write(envelope)

	_, err := readHandshake(bufio.NewReader(&buf))
	var gone *ErrSessionGone
	if !errors.As(err, &gone) {
		t.Fatalf("应归类为会话失效，得到 %v", err)
	}
	if gone.Code != codeSessionGone {
		t.Errorf("码 = %d，期望 %d", gone.Code, codeSessionGone)
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
	if src, dst := info.key.srcString(), info.key.dstString(); src != "10.0.0.1" || dst != "10.1.2.3" {
		t.Errorf("五元组地址 = %s -> %s", src, dst)
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

func TestParseIPv4ResourceHostAndPortRange(t *testing.T) {
	for _, tc := range []struct{ host, want string }{
		{"10.0.0.7", "10.0.0.7/32"},
		{"10.0.0.7/24", "10.0.0.0/24"},
		{"255.255.255.255/0", "0.0.0.0/0"},
		{"255.255.255.255/32", "255.255.255.255/32"},
	} {
		got, ok := parseIPv4ResourceHost(tc.host)
		if !ok || got.String() != tc.want {
			t.Errorf("%q = %v（%v），期望 %s", tc.host, got, ok, tc.want)
		}
	}
	for _, host := range []string{"", "example.com", "*.example.com", "10.0.0.1-10.0.0.5", "10.0.0.0/33", "256.0.0.1", "010.0.0.1", "10.0.0.1 ", "::1", "::/0", "::ffff:10.0.0.1", "::ffff:10.0.0.0/120"} {
		if _, ok := parseIPv4ResourceHost(host); ok {
			t.Errorf("%q 不应进入 IPv4 资源表", host)
		}
	}
	for _, tc := range []struct {
		spec   string
		lo, hi uint16
	}{
		{"", 1, 65535}, {"0", 1, 65535}, {"443", 443, 443},
		{"8000-8100", 8000, 8100}, {"65535", 65535, 65535},
	} {
		lo, hi, ok := parsePortRange(tc.spec)
		if !ok || lo != tc.lo || hi != tc.hi {
			t.Errorf("%q = %d-%d（%v），期望 %d-%d", tc.spec, lo, hi, ok, tc.lo, tc.hi)
		}
	}
	for _, spec := range []string{"abc", "443-80", "-1", "65536", "80,443", "80-", "1-2-3", "0-65535", "+80"} {
		lo, hi, ok := parsePortRange(spec)
		if ok || lo != 0 || hi != 0 {
			t.Errorf("%q 不应产生可用端口段：%d-%d（%v）", spec, lo, hi, ok)
		}
	}
}

func TestResourceTableMatchAndNodes(t *testing.T) {
	raw := []byte(`{"code":0,"data":{"appList":{"data":{"appInfo":[{"apps":[
		{"id":"app-a","nodeGroupId":"groupWan","accessModel":"L3VPN","addressList":[
			{"protocol":"tcp","port":"443","host":"10.1.0.0/16"},
			{"protocol":"all","port":"0","host":"172.16.0.0/29"}]},
		{"id":"app-b","nodeGroupId":"groupWan","accessModel":"Web","addressList":[
			{"protocol":"all","port":"0","host":"10.2.0.0/16"}]}
		]}],"config":{"nodeGroupConf":{"majorNodeGroup":{"id":"groupWan"},"nodeGroupList":[
		{"id":"groupWan","addressInfo":[{"address":"node-a:441","type":"wan"}]},
		{"id":"groupLan","addressInfo":[{"address":"node-b:441","type":"lan"}]}]}}}},
		"sdpPolicy":{"data":{"clientOption":{"dnsOptionV2":{"firstDNS":"10.0.0.53"}}}}}}`)

	table, err := parseResourceTable(raw, "vpn.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(table.IP) != 2 {
		t.Fatalf("资源条数 = %d，期望 2（Web 资源不参与 L3 匹配）", len(table.IP))
	}

	cases := []struct {
		name  string
		dst   string
		proto uint8
		port  uint16
		ok    bool
	}{
		{"命中 TCP 资源", "10.1.2.3", protoTCP, 443, true},
		{"端口不在范围内", "10.1.2.3", protoTCP, 80, false},
		{"协议不匹配", "10.1.2.3", protoUDP, 443, false},
		{"命中 all 区间", "172.16.0.5", protoUDP, 53, true},
		// ICMP 没有端口，协议层传上来的是 0：规则里的端口段是 1-65535，
		// 拿 0 去比会把整个网段的 ICMP 判成表外（实测踩过：ping 校园网全丢）。
		{"ICMP 命中 all 区间", "172.16.0.5", protoICMP, 0, true},
		{"ICMP 不该命中只有 TCP 的规则", "10.1.2.3", protoICMP, 0, false},
		// TCP/UDP 里目的端口 0 是畸形包：按协议区分之后它不再绕过端口判断。
		{"TCP 目的端口 0 不命中 443 规则", "10.1.2.3", protoTCP, 0, false},
		{"区间之外", "172.16.0.10", protoUDP, 53, false},
		{"表外地址", "8.8.8.8", protoTCP, 53, false},
	}
	for _, c := range cases {
		dst := netip.MustParseAddr(c.dst)
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

// 非法端口格式必须跳过规则，不能扩大客户端鉴权范围。
func TestResourceTableRejectsAndCountsInvalidPorts(t *testing.T) {
	raw := []byte(`{"data":{"appList":{"data":{"appInfo":[{"apps":[
		{"id":"app-a","accessModel":"L3VPN","addressList":[
			{"protocol":"tcp","port":"80,443","host":"10.3.0.0/16"}]}
		]}],"config":{"nodeGroupConf":{"majorNodeGroup":{"id":"g"},"nodeGroupList":[
		{"id":"g","addressInfo":[{"address":"node-a:441","type":"wan"}]}]}}}}}}`)
	table, err := parseResourceTable(raw, "vpn.test")
	if err != nil {
		t.Fatal(err)
	}
	if table.badPorts != 1 {
		t.Errorf("看不懂的端口段计数 = %d，期望 1", table.badPorts)
	}
	if _, _, ok := table.match(netip.MustParseAddr("10.3.4.5"), protoTCP, 12345); ok {
		t.Error("非法端口规则扩大了访问范围")
	}
}

func TestParseResourceTableSubstitutesHostPlaceholder(t *testing.T) {
	raw := []byte(`{"data":{"appList":{"data":{"config":{"nodeGroupConf":{"majorNodeGroup":{"id":"g"},
		"nodeGroupList":[{"id":"g","addressInfo":[{"address":"{{sdpcHost}}","type":"wan"}]}]}}}}}}`)
	table, err := parseResourceTable(raw, "vpn.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(table.NodeGroup["g"]) != 1 || table.NodeGroup["g"][0].Address != "vpn.test:441" {
		t.Errorf("节点地址 = %v，期望 vpn.test:441", table.NodeGroup)
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

// TestResourceTableDropsMalformedNodes 回归：资源表里的畸形节点地址必须在校验
// 阶段丢掉，不能进探活、日志与 CONNECT 请求行。
func TestResourceTableDropsMalformedNodes(t *testing.T) {
	raw := []byte(`{"code":0,"data":{"appList":{"data":{"appInfo":[{"apps":[
		{"id":"app-a","nodeGroupId":"g","accessModel":"L3VPN","addressList":[
			{"protocol":"tcp","port":"443","host":"10.1.0.0/16"}]}]}],
		"config":{"nodeGroupConf":{"majorNodeGroup":{"id":"g"},"nodeGroupList":[
		{"id":"g","addressInfo":[
			{"address":"node-a:441","type":"wan"},
			{"address":"evil\r\nGET http://127.0.0.1:8080/admin HTTP/1.1","type":"wan"},
			{"address":"node-b:0","type":"wan"},
			{"address":"node-c","type":"lan"}]}]}}}}}}`)

	table, err := parseResourceTable(raw, "vpn.test")
	if err != nil {
		t.Fatal(err)
	}
	if table.badNodes != 2 {
		t.Errorf("丢弃的节点数 = %d，期望 2（注入串与端口 0；缺端口的补 :441 之后合法）", table.badNodes)
	}
	nodes := table.candidateNodes("g")
	if len(nodes) != 2 || nodes[0] != "node-a:441" || nodes[1] != "node-c:441" {
		t.Fatalf("候选节点 = %v，期望 [node-a:441 node-c:441]", nodes)
	}
}

// TestParsePacketAllocations 钉住上行热路径的分配预算：每包解析不分配。
//
// 键原来用 net.IP.String() 拼字符串，实测 2.00 次分配/包；换成 4 字节数组之后
// 这条路径不再分配任何东西。反向验证：把 parsePacket 改回字符串键，本用例红。
func TestParsePacketAllocations(t *testing.T) {
	pkt := ipv4TCP("10.0.0.1", "10.1.2.3", 1234, 443, []byte("payload"))
	info, err := parsePacket(pkt)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	allocs := testing.AllocsPerRun(200, func() {
		if _, err := parsePacket(pkt); err != nil {
			t.Fatalf("解析失败: %v", err)
		}
	})
	if allocs != 0 {
		t.Errorf("parsePacket 每包 %v 次分配，期望 0", allocs)
	}

	// 键是值类型：查流表（命中已有条目）同样不该分配。
	flows := newFlowTable()
	flows.queuePacket(info, "app", pkt)
	auth := flows.pendingAuth(1)
	flows.completeAuth(auth[0].authID, "tok", nil)
	if allocs := testing.AllocsPerRun(200, func() {
		flows.queuePacket(info, "app", pkt)
	}); allocs != 0 {
		t.Errorf("流表查询每包 %v 次分配，期望 0", allocs)
	}
}
