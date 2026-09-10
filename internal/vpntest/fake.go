// Package vpntest 提供协议层的测试替身：一个脚本化的 portal HTTP 接口
// 和一条内存里的假隧道服务端。
//
// 有了它们，协议层和业务层的回归测试都不需要连真实的校园服务端：
// 真实账号有配额限制，跑一次测试的代价可能是几分钟的封禁。
package vpntest

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	loginPageOnce sync.Once
	loginPageBody string
)

// LoginAuthPage 返回一份完整的登录页响应（含真实可用的 RSA 公钥）。
//
// 公钥是现生成的：仓库里不该出现写死的假模数，而加密口令这一步
// 需要一个真能用的大模数。
func LoginAuthPage() string {
	loginPageOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		loginPageBody = "<Auth><TwfID>0123456789abcdef</TwfID>" +
			"<RSA_ENCRYPT_KEY>" + key.N.Text(16) + "</RSA_ENCRYPT_KEY>" +
			"<RSA_ENCRYPT_EXP>" + strconv.Itoa(key.E) + "</RSA_ENCRYPT_EXP>" +
			"<CSRF_RAND_CODE>csrftoken</CSRF_RAND_CODE></Auth>"
	})
	return loginPageBody
}

// Response 是一条脚本化的 HTTP 响应。
type Response struct {
	// Status 为 0 时按 200 处理。
	Status int
	Body   string
	// Chunks 非空时按这些分片写出，用来模拟"响应分多个 TCP 段到达"。
	Chunks [][]byte
	// Delay 是每个分片之间的延迟。
	Delay time.Duration
}

// Request 是一条被记录下来的请求。
type Request struct {
	Method string
	Path   string
	Query  url.Values
	Form   url.Values
	Cookie string
}

// Portal 是 portal 接口的测试替身。
type Portal struct {
	mu       sync.Mutex
	routes   map[string][]Response
	requests []Request
	fallback func(path string) Response
}

// NewPortal 构造一个空的 portal 替身。未注册的路径返回 404。
func NewPortal() *Portal {
	return &Portal{routes: make(map[string][]Response)}
}

// On 注册某个路径的响应，按注册顺序依次返回。
func (p *Portal) On(path string, resps ...Response) *Portal {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.routes[path] = append(p.routes[path], resps...)
	return p
}

// Set 覆盖某个路径的响应队列。
func (p *Portal) Set(path string, resps ...Response) *Portal {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.routes[path] = append([]Response(nil), resps...)
	return p
}

// SetFallback 设置未命中路径时的响应。
func (p *Portal) SetFallback(f func(path string) Response) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fallback = f
}

// Requests 返回已记录的请求。
func (p *Portal) Requests() []Request {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Request, len(p.requests))
	copy(out, p.requests)
	return out
}

// Count 返回某个路径被请求的次数。
func (p *Portal) Count(path string) int {
	n := 0
	for _, r := range p.Requests() {
		if r.Path == path {
			n++
		}
	}
	return n
}

// LastForm 返回某个路径最后一次提交的表单。
func (p *Portal) LastForm(path string) url.Values {
	for _, r := range p.Requests() {
		if r.Path == path {
			return r.Form
		}
	}
	return nil
}

// HTTPClient 返回一个使用本替身的 HTTP 客户端。
func (p *Portal) HTTPClient() *http.Client { return &http.Client{Transport: p} }

// RoundTrip 实现 http.RoundTripper。
func (p *Portal) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := Request{
		Method: req.Method,
		Path:   req.URL.Path,
		Query:  req.URL.Query(),
		Cookie: req.Header.Get("Cookie"),
	}
	if req.Body != nil {
		raw, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, err
		}
		form, err := url.ParseQuery(string(raw))
		if err == nil {
			rec.Form = form
		}
	}

	p.mu.Lock()
	p.requests = append(p.requests, rec)
	resp, ok := p.next(req.URL.Path)
	p.mu.Unlock()

	if !ok {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Status:     "404 Not Found",
			Body:       io.NopCloser(strings.NewReader("not scripted: " + req.URL.Path)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}

	status := resp.Status
	if status == 0 {
		status = http.StatusOK
	}

	body := &chunkReader{chunks: resp.Chunks, delay: resp.Delay}
	if len(body.chunks) == 0 {
		body.chunks = [][]byte{[]byte(resp.Body)}
	}
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Body:       body,
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// next 取出下一个脚本化响应。调用方需持有锁。
func (p *Portal) next(path string) (Response, bool) {
	if queue := p.routes[path]; len(queue) > 0 {
		resp := queue[0]
		if len(queue) == 1 {
			delete(p.routes, path)
		} else {
			p.routes[path] = queue[1:]
		}
		return resp, true
	}
	if p.fallback != nil {
		return p.fallback(path), true
	}
	return Response{}, false
}

// chunkReader 按分片吐数据，模拟短读。
type chunkReader struct {
	chunks [][]byte
	delay  time.Duration
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	chunk := r.chunks[0]
	r.chunks = r.chunks[1:]
	if r.delay > 0 && len(r.chunks) > 0 {
		time.Sleep(r.delay)
	}
	n := copy(p, chunk)
	if n < len(chunk) {
		// 没拷完的留在下一轮，保持顺序。
		r.chunks = append([][]byte{chunk[n:]}, r.chunks...)
	}
	return n, nil
}

func (r *chunkReader) Close() error { return nil }

// TunnelStats 是一次测试里假隧道服务端的统计。
type TunnelStats struct {
	Connections int
	QueryIP     int
	Streams     []byte
	Closed      int
	Uplink      [][]byte
	Downlink    int
}

// Tunnel 是假隧道服务端：每次建连返回一条内存管道，并按协议应答。
type Tunnel struct {
	mu sync.Mutex

	sessionID []byte
	ip        [4]byte

	rejectQueryIP byte
	rejectStream  map[byte]byte

	connections int
	queryIP     int
	streams     []byte
	closed      int
	uplink      [][]byte
	downlink    int

	recvConn net.Conn
	recvCh   chan struct{}
	onUplink func([]byte)
}

// NewTunnel 构造假隧道服务端。
func NewTunnel() *Tunnel {
	return &Tunnel{
		sessionID:    []byte("0123456789abcdef0123456789abcdef"),
		ip:           [4]byte{172, 29, 56, 18},
		rejectStream: make(map[byte]byte),
		recvCh:       make(chan struct{}, 8),
	}
}

// SetSessionID 设置 portal-token 连接上返回的 ServerHello SessionId。
func (t *Tunnel) SetSessionID(id []byte) {
	t.mu.Lock()
	t.sessionID = id
	t.mu.Unlock()
}

// SetIP 设置 query-ip 分配到的地址。
func (t *Tunnel) SetIP(ip [4]byte) {
	t.mu.Lock()
	t.ip = ip
	t.mu.Unlock()
}

// RejectQueryIP 让 query-ip 用指定的控制码拒绝。
func (t *Tunnel) RejectQueryIP(code byte) {
	t.mu.Lock()
	t.rejectQueryIP = code
	t.mu.Unlock()
}

// AllowQueryIP 恢复正常应答。
func (t *Tunnel) AllowQueryIP() {
	t.mu.Lock()
	t.rejectQueryIP = 0
	t.mu.Unlock()
}

// RejectStream 让指定方向的流握手用指定控制码拒绝。
func (t *Tunnel) RejectStream(kind, code byte) {
	t.mu.Lock()
	t.rejectStream[kind] = code
	t.mu.Unlock()
}

// OnUplink 注册上行数据回调。
func (t *Tunnel) OnUplink(f func([]byte)) {
	t.mu.Lock()
	t.onUplink = f
	t.mu.Unlock()
}

// Stats 返回统计快照。
func (t *Tunnel) Stats() TunnelStats {
	t.mu.Lock()
	defer t.mu.Unlock()
	stats := TunnelStats{
		Connections: t.connections,
		QueryIP:     t.queryIP,
		Closed:      t.closed,
		Downlink:    t.downlink,
	}
	stats.Streams = append(stats.Streams, t.streams...)
	for _, p := range t.uplink {
		stats.Uplink = append(stats.Uplink, append([]byte(nil), p...))
	}
	return stats
}

// WaitRecvStream 等待下行流建立。
func (t *Tunnel) WaitRecvStream(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		t.mu.Lock()
		conn := t.recvConn
		t.mu.Unlock()
		if conn != nil {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return fmt.Errorf("等待下行流建立超时")
}

// SendDownlink 从服务端侧往客户端推一个下行包。
func (t *Tunnel) SendDownlink(pkt []byte) error {
	t.mu.Lock()
	conn := t.recvConn
	t.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("下行流尚未建立")
	}
	if _, err := conn.Write(pkt); err != nil {
		return err
	}
	t.mu.Lock()
	t.downlink++
	t.mu.Unlock()
	return nil
}

// CloseRecvStream 关闭服务端侧的下行流，模拟隧道中途断开。
func (t *Tunnel) CloseRecvStream() {
	t.mu.Lock()
	conn := t.recvConn
	t.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
}

// Dial 是注入给 vpn.Options 的 TLSDialFunc。
func (t *Tunnel) Dial(ctx context.Context) (net.Conn, error) {
	client, server := net.Pipe()
	t.mu.Lock()
	t.connections++
	id := append([]byte(nil), t.sessionID...)
	t.mu.Unlock()

	go t.serve(server)
	return &clientConn{Conn: client, sessionID: id}, nil
}

// clientConn 在客户端侧伪造 ServerHello 的 SessionId。
type clientConn struct {
	net.Conn
	sessionID []byte
}

// ServerHelloSessionID 实现协议层需要的接口。
func (c *clientConn) ServerHelloSessionID() ([]byte, error) {
	return c.sessionID, nil
}

// serve 按客户端发来的第一段报文决定扮演哪个角色。
func (t *Tunnel) serve(server net.Conn) {
	defer func() {
		server.Close()
		t.mu.Lock()
		t.closed++
		t.mu.Unlock()
	}()

	r := bufio.NewReader(server)
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return
	}

	switch {
	case bytes.Equal(head, []byte("GET ")):
		t.servePortalToken(r, server)
	case head[0] == 0x00:
		t.serveQueryIP(r, server)
	case head[0] == 0x05 || head[0] == 0x06:
		t.serveStream(r, server, head[0])
	}
}

// servePortalToken 应答一次 portal 请求，SessionId 由 clientConn 提供。
func (t *Tunnel) servePortalToken(r *bufio.Reader, server net.Conn) {
	if err := readHTTPRequests(r, 2); err != nil {
		return
	}
	if _, err := server.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")); err != nil {
		return
	}
	io.Copy(io.Discard, r)
}

// serveQueryIP 应答 query-ip，然后保持连接打开。
func (t *Tunnel) serveQueryIP(r *bufio.Reader, server net.Conn) {
	if _, err := io.CopyN(io.Discard, r, streamTokenLen+8); err != nil {
		return
	}

	t.mu.Lock()
	reject := t.rejectQueryIP
	ip := t.ip
	t.queryIP++
	t.mu.Unlock()

	if reject != 0 {
		server.Write([]byte{reject})
		return
	}

	reply := make([]byte, 36)
	copy(reply[4:8], ip[:])
	if _, err := server.Write(reply); err != nil {
		return
	}
	io.Copy(io.Discard, r)
}

// serveStream 应答流握手，然后把收到的数据交给回调。
func (t *Tunnel) serveStream(r *bufio.Reader, server net.Conn, kind byte) {
	if _, err := io.CopyN(io.Discard, r, streamTokenLen+8); err != nil {
		return
	}

	t.mu.Lock()
	reject := t.rejectStream[kind]
	t.streams = append(t.streams, kind)
	if kind == 0x06 {
		t.recvConn = server
	}
	t.mu.Unlock()

	if kind == 0x06 {
		select {
		case t.recvCh <- struct{}{}:
		default:
		}
	}

	if reject != 0 {
		server.Write([]byte{reject})
		return
	}
	// 回执是"流类型"而不是请求里的操作码：0x06 请求下行流，回执 0x01；
	// 0x05 请求上行流，回执 0x02。
	ack := byte(0x01)
	if kind == 0x05 {
		ack = 0x02
	}
	if _, err := server.Write([]byte{ack}); err != nil {
		return
	}

	buf := make([]byte, 65535)
	for {
		n, err := r.Read(buf)
		if n > 0 && kind == 0x05 {
			pkt := append([]byte(nil), buf[:n]...)
			t.mu.Lock()
			t.uplink = append(t.uplink, pkt)
			cb := t.onUplink
			t.mu.Unlock()
			if cb != nil {
				cb(pkt)
			}
		}
		if err != nil {
			return
		}
	}
}

// streamTokenLen 与协议层保持一致：4 字节操作码 + 48 字节 token + 8 字节 + 4 字节反序地址。
const streamTokenLen = 48

// readHTTPRequests 读若干个完整的 HTTP 请求头。
func readHTTPRequests(r *bufio.Reader, n int) error {
	for i := 0; i < n; i++ {
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return err
			}
			if line == "\r\n" {
				break
			}
		}
	}
	return nil
}
