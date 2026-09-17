package ztna

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
)

// 线上格式。这些常量是与服务端的契约，改动前先看 wire_format_test.go：
// 里面把握手信封、VIP 帧、数据帧逐字节钉死了。
const (
	// Version 是隧道帧的版本字节，所有帧都以它开头。
	Version byte = 0x05

	// 握手：请求 05 01 D0，方法响应 05 D0，认证信封以 0x53 开头。
	cmdHandshake    byte = 0x01
	methodHandshake byte = 0xD0
	envelopeVersion byte = 0x53

	// 逐流鉴权：请求 05 13，响应 05 93。
	cmdAuthReq  byte = 0x13
	cmdAuthResp byte = 0x93

	// 数据：请求 05 14，响应 05 94。
	cmdDataReq  byte = 0x14
	cmdDataResp byte = 0x94

	// 心跳：请求 05 15 00 00，响应 05 95 00 00。
	cmdHeartbeatReq  byte = 0x15
	cmdHeartbeatResp byte = 0x95

	// 服务端下发地址（三家参考实现都命名为 second VIP）：载荷是一份地址
	// 列表，可能同时含 IPv4 与 IPv6。真正的主地址异步变更（0x97）本实现
	// 不认识，遇到未知命令按协议错误处理并重连。
	cmdVIPUpdate byte = 0x96

	// 握手请求里携带的地址类型：1 = IPv4（虚拟地址体 6 字节）。
	addrTypeIPv4 byte = 0x01

	// handshakeFrameLimit 是握手阶段的信封帧数上限。
	//
	// 握手正常只有一两帧（一个鉴权结果加一个虚拟地址），而读循环本身没有尽头：
	// 对端一直刷帧就能让它一直跑下去，每帧还会新分配一块载荷。给个上限，超出
	// 就按协议错误收场。
	handshakeFrameLimit = 32
)

// parseVIPListPayload 从 0x96 的载荷里尽力取出地址列表。
//
// 三家参考实现都把它命名为 second VIP，但载荷形态并不统一：见过
// {"data":{"vip":…,"vip6":…}}，也见过地址数组。这里不猜结构，直接把 JSON
// 里所有字符串值递归收集起来，能解析成 IP 的就算地址。取不到就当这一帧没
// 发生——服务端将来换形态也不会把连接搞坏。
//
// 对象里的键按字典序走：Go 的 map 迭代顺序是随机的，不排的话同一份载荷可能
// 给出不同的顺序，而调用方取的是"第一个 IPv4"。
func parseVIPListPayload(payload []byte) []net.IP {
	var value any
	if err := json.Unmarshal(payload, &value); err != nil {
		return nil
	}
	var out []net.IP
	var walk func(v any)
	walk = func(v any) {
		switch typed := v.(type) {
		case string:
			if ip := net.ParseIP(strings.TrimSpace(typed)); ip != nil {
				out = append(out, ip)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		case map[string]any:
			keys := make([]string, 0, len(typed))
			for k := range typed {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(typed[k])
			}
		}
	}
	walk(value)
	return out
}

// vipBodyLen 返回给定地址类型的虚拟地址体长度。
//
// 实测确认 addrType=1 的体是 6 字节（4 字节地址 + 2 字节未知），
// 只读 4 字节会让后续帧整体错位。
func vipBodyLen(addrType byte) (int, error) {
	switch addrType {
	case 1:
		return 6, nil
	case 4:
		return 18, nil
	case 5:
		return 22, nil
	default:
		return 0, &ProtocolError{What: "未知的虚拟地址类型", Got: fmt.Sprintf("0x%02x", addrType)}
	}
}

// parseVIP 从虚拟地址体里取出地址（只认 IPv4）。
func parseVIP(addrType byte, body []byte) net.IP {
	if len(body) < 4 {
		return nil
	}
	if addrType == 1 || addrType == 5 {
		return net.IPv4(body[0], body[1], body[2], body[3])
	}
	return nil
}

// handshakeRequest 构造隧道握手请求：
//
//	05 01 D0 | 53 00 <u16 len> {"sid":"..."} | 05 04 00 <addrType> 00*6
//
// 长度按实际 JSON 字节数计算——服务端不认写死的值。
func handshakeRequest(sid string) []byte {
	payload := []byte(fmt.Sprintf("{%q:%q}", "sid", sid))
	out := make([]byte, 0, 3+2+2+len(payload)+10)
	out = append(out, Version, cmdHandshake, methodHandshake, envelopeVersion, 0x00)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(payload)))
	out = append(out, l[:]...)
	out = append(out, payload...)
	out = append(out, Version, 0x04, 0x00, addrTypeIPv4, 0, 0, 0, 0, 0, 0)
	return out
}

// handshakeResult 是握手成功后服务端给出的东西。
type handshakeResult struct {
	VIP      net.IP
	DeviceID string
}

// readHandshake 读握手响应。服务端可能先回一个空信封再回真正的结果，
// 所以这里按帧循环读到 VIP 为止。
func readHandshake(r *bufio.Reader) (handshakeResult, error) {
	var res handshakeResult

	method := make([]byte, 2)
	if _, err := io.ReadFull(r, method); err != nil {
		return res, fmt.Errorf("读方法响应: %w", err)
	}
	if method[0] != Version || method[1] != methodHandshake {
		return res, &ProtocolError{What: "非预期的方法响应", Got: hex2(method)}
	}

	for frames := 0; ; frames++ {
		if frames >= handshakeFrameLimit {
			return res, &ProtocolError{What: "握手帧数超过上限", Got: fmt.Sprintf("%d 帧", frames)}
		}
		head := make([]byte, 4)
		if _, err := io.ReadFull(r, head); err != nil {
			return res, fmt.Errorf("读信封头: %w", err)
		}
		switch head[0] {
		case envelopeVersion:
			// 53 <status> <u16 len> <payload>：鉴权结果，可能重复出现。
			status := head[1]
			n := int(binary.BigEndian.Uint16(head[2:4]))
			payload := make([]byte, n)
			if _, err := io.ReadFull(r, payload); err != nil {
				return res, fmt.Errorf("读信封体: %w", err)
			}
			if status != 0 {
				return res, &ProtocolError{What: "握手被拒", Got: fmt.Sprintf("status=%d %s", status, truncateForError(payload))}
			}
			if code, msg, ok := parseEnvelopeCode(payload); ok && code != 0 {
				// 状态字节为 0 也可能是失败：会话失效时服务端正是这么回的。
				// 会话失效码按"需要重新登录"归类，别包成协议错误——那会让调用方
				// 按通用失败重试三次，而不是直接告诉用户重新登录。
				if code == codeSessionGone {
					return res, &ErrSessionGone{Code: code, Message: msg}
				}
				return res, &ProtocolError{What: fmt.Sprintf("握手被拒（%d）", code), Got: msg}
			}
		case Version:
			// 05 <status> <reserved> <addrType> <body>：虚拟地址。
			addrType := head[3]
			bodyLen, err := vipBodyLen(addrType)
			if err != nil {
				return res, err
			}
			body := make([]byte, bodyLen)
			if _, err := io.ReadFull(r, body); err != nil {
				return res, fmt.Errorf("读虚拟地址: %w", err)
			}
			if head[1] != 0 {
				return res, &ProtocolError{What: "虚拟地址下发失败", Got: fmt.Sprintf("status=%d", head[1])}
			}
			res.VIP = parseVIP(addrType, body)
			if res.VIP == nil {
				return res, &ProtocolError{What: "服务端没有下发 IPv4 地址"}
			}
			return res, nil
		default:
			return res, &ProtocolError{What: "未知的握手帧", Got: hex2(head[:1])}
		}
	}
}

// encodeDataFrame 构造数据帧：
//
//	05 14 <u8 tokenLen> <token> 00 00 <u8 count> (<u16 len> <包>)*
//
// 前提：count 是单字节，调用方每次最多传 authBatchSize（32）个包；在调用点
// 提高批量之前先改这里，否则计数会被截断。
func encodeDataFrame(token string, pkts ...[]byte) ([]byte, error) {
	if len(token) > 0xFF {
		return nil, &ProtocolError{What: "会话令牌过长", Got: fmt.Sprintf("%d", len(token))}
	}
	size := 3 + len(token) + 2 + 1
	for _, p := range pkts {
		size += 2 + len(p)
		if len(p) == 0 || len(p) > 0xFFFF {
			return nil, &ProtocolError{What: "IP 包长度非法", Got: fmt.Sprintf("%d", len(p))}
		}
	}
	out := make([]byte, 0, size)
	out = append(out, Version, cmdDataReq, byte(len(token)))
	out = append(out, token...)
	out = append(out, 0x00, 0x00, byte(len(pkts)))
	for _, p := range pkts {
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(p)))
		out = append(out, l[:]...)
		out = append(out, p...)
	}
	return out, nil
}

// encodeAuthRequest 构造逐流鉴权请求帧：05 13 <u16 len> <JSON>。
func encodeAuthRequest(body []byte) ([]byte, error) {
	if len(body) > 0xFFFF {
		return nil, &ProtocolError{What: "鉴权请求过长"}
	}
	out := make([]byte, 0, 3+len(body))
	out = append(out, Version, cmdAuthReq, 0x00, 0x00)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(body)))
	return append(out, body...), nil
}

// encodeHeartbeat 构造心跳帧：05 15 00 00。
func encodeHeartbeat() []byte { return []byte{Version, cmdHeartbeatReq, 0x00, 0x00} }

// frame 是读出来的一帧。
type frame struct {
	cmd     byte
	status  byte
	payload []byte
}

// readFrame 读一帧。0x94/0x95 是长度前缀，0x93/0x96 多一个状态字节。
func readFrame(r *bufio.Reader) (frame, error) {
	var f frame
	head := make([]byte, 2)
	if _, err := io.ReadFull(r, head); err != nil {
		return f, err
	}
	if head[0] != Version {
		return f, &ProtocolError{What: "帧版本非 0x05", Got: hex2(head[:1])}
	}
	f.cmd = head[1]
	switch f.cmd {
	case cmdDataResp, cmdHeartbeatResp:
		var l [2]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return f, err
		}
		f.payload = make([]byte, int(binary.BigEndian.Uint16(l[:])))
		if _, err := io.ReadFull(r, f.payload); err != nil {
			return f, err
		}
	case cmdAuthResp, cmdVIPUpdate:
		var l [3]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return f, err
		}
		f.status = l[0]
		f.payload = make([]byte, int(binary.BigEndian.Uint16(l[1:3])))
		if _, err := io.ReadFull(r, f.payload); err != nil {
			return f, err
		}
	default:
		return f, &ProtocolError{What: "未知的隧道帧", Got: hex2(head)}
	}
	return f, nil
}

// splitPackets 把一段字节按 IP 头里的总长度切成若干 IP 包，
// 尾部的半包留给下一次读取。
func splitPackets(stream []byte) (pkts [][]byte, rest []byte, err error) {
	for len(stream) > 0 {
		if stream[0]>>4 != 4 {
			return nil, nil, &ProtocolError{What: "隧道里出现非 IPv4 数据", Got: hex2(stream[:1])}
		}
		if len(stream) < 4 {
			return pkts, stream, nil
		}
		n := int(binary.BigEndian.Uint16(stream[2:4]))
		if n < 20 {
			return nil, nil, &ProtocolError{What: "IP 包长度非法", Got: fmt.Sprintf("%d", n)}
		}
		if len(stream) < n {
			return pkts, stream, nil
		}
		pkts = append(pkts, stream[:n:n])
		stream = stream[n:]
	}
	return pkts, nil, nil
}

func hex2(b []byte) string { return fmt.Sprintf("%02x", b) }

func truncateForError(b []byte) string {
	const max = 120
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "..."
}
