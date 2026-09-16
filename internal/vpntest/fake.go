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
	Path   string
	Form   url.Values
	Cookie string
}

// Portal 是 portal 接口的测试替身。
type Portal struct {
	mu       sync.Mutex
	routes   map[string][]Response
	requests []Request
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
		Path:   req.URL.Path,
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
	// Closed 是服务端侧关闭的连接数，用来断言"流被关掉了"。
	Closed int
	// Uplink 是上行方向收到的数据。
	Uplink [][]byte
}

// Tunnel 是假隧道服务端：每次建连返回一条内存管道，并按协议应答。
type Tunnel struct {
	mu sync.Mutex

	sessionID []byte
	ip        [4]byte

	rejectQueryIP byte
	rejectStream  map[byte]byte

	closed int
	uplink [][]byte

	// 最近一次收到的握手报文原文，用于逐字节核对线上格式。
	queryFrame  []byte
	streamFrame map[byte][]byte

	recvConn net.Conn
	// ready 记录某个方向的流握手是否已经被收到（通道只关一次），供 WaitStream /
	// WaitRecvStream 等待，避免测试靠轮询赌时序。
	ready     map[byte]chan struct{}
	readyOnce map[byte]*sync.Once
	// uplinkReady 在第一份上行数据被收到时关闭，供 WaitUplink 等待。
	uplinkReady chan struct{}
	uplinkOnce  sync.Once
}

// NewTunnel 构造假隧道服务端。
func NewTunnel() *Tunnel {
	return &Tunnel{
		sessionID:    []byte("0123456789abcdef0123456789abcdef"),
		ip:           [4]byte{172, 29, 56, 18},
		rejectStream: make(map[byte]byte),
		ready: map[byte]chan struct{}{
			streamKindSend: make(chan struct{}),
			streamKindRecv: make(chan struct{}),
		},
		readyOnce: map[byte]*sync.Once{
			streamKindSend: new(sync.Once),
			streamKindRecv: new(sync.Once),
		},
		uplinkReady: make(chan struct{}),
		streamFrame: make(map[byte][]byte),
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

// RejectStream 让指定方向的流握手用指定控制码拒绝。
func (t *Tunnel) RejectStream(kind, code byte) {
	t.mu.Lock()
	t.rejectStream[kind] = code
	t.mu.Unlock()
}

// Stats 返回统计快照。
func (t *Tunnel) Stats() TunnelStats {
	t.mu.Lock()
	defer t.mu.Unlock()
	stats := TunnelStats{
		Closed: t.closed,
	}
	for _, p := range t.uplink {
		stats.Uplink = append(stats.Uplink, append([]byte(nil), p...))
	}
	return stats
}

// WaitRecvStream 等待下行流建立，超时返回错误。
func (t *Tunnel) WaitRecvStream(timeout time.Duration) error {
	return t.WaitStream(streamKindRecv, timeout)
}

// WaitStream 等待某个方向的流握手被收到（即流已建立），超时返回错误。
func (t *Tunnel) WaitStream(kind byte, timeout time.Duration) error {
	t.mu.Lock()
	ready := t.ready[kind]
	t.mu.Unlock()
	if ready == nil {
		return fmt.Errorf("未知的流方向: %#x", kind)
	}
	select {
	case <-ready:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("等待流 %#x 建立超时", kind)
	}
}

// WaitUplink 等待第一份上行数据被收到，超时返回错误。
func (t *Tunnel) WaitUplink(timeout time.Duration) error {
	select {
	case <-t.uplinkReady:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("等待上行数据超时")
	}
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

// QueryFrame 返回最近一次收到的 query-ip 报文原文。
func (t *Tunnel) QueryFrame() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]byte(nil), t.queryFrame...)
}

// StreamFrame 返回某方向最近一次收到的流握手报文原文。
func (t *Tunnel) StreamFrame(kind byte) []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]byte(nil), t.streamFrame[kind]...)
}

// Dial 是注入给 vpn.Options 的 TLSDialFunc。
func (t *Tunnel) Dial(ctx context.Context) (net.Conn, error) {
	client, server := net.Pipe()
	t.mu.Lock()
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
		t.serveQueryIP(r, server, head)
	case head[0] == streamKindSend || head[0] == streamKindRecv:
		t.serveStream(r, server, head[0], head)
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
func (t *Tunnel) serveQueryIP(r *bufio.Reader, server net.Conn, head []byte) {
	frame := append([]byte(nil), head...)
	rest := make([]byte, QueryFrameLen-4)
	if _, err := io.ReadFull(r, rest); err != nil {
		return
	}
	frame = append(frame, rest...)

	t.mu.Lock()
	reject := t.rejectQueryIP
	ip := t.ip
	t.queryFrame = frame
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
func (t *Tunnel) serveStream(r *bufio.Reader, server net.Conn, kind byte, head []byte) {
	frame := append([]byte(nil), head...)
	rest := make([]byte, StreamFrameLen-4)
	if _, err := io.ReadFull(r, rest); err != nil {
		return
	}
	frame = append(frame, rest...)

	t.mu.Lock()
	reject := t.rejectStream[kind]
	t.streamFrame[kind] = frame
	if kind == streamKindRecv {
		t.recvConn = server
	}
	ready, readyOnce := t.ready[kind], t.readyOnce[kind]
	t.mu.Unlock()

	if readyOnce != nil {
		readyOnce.Do(func() { close(ready) })
	}

	if reject != 0 {
		server.Write([]byte{reject})
		return
	}
	// 回执是"流类型"而不是请求里的操作码：下行流请求回执 0x01，
	// 上行流请求回执 0x02。
	ack := byte(0x01)
	if kind == streamKindSend {
		ack = 0x02
	}
	if _, err := server.Write([]byte{ack}); err != nil {
		return
	}

	buf := make([]byte, 65535)
	for {
		n, err := r.Read(buf)
		if n > 0 && kind == streamKindSend {
			pkt := append([]byte(nil), buf[:n]...)
			t.mu.Lock()
			t.uplink = append(t.uplink, pkt)
			t.mu.Unlock()
			t.uplinkOnce.Do(func() { close(t.uplinkReady) })
		}
		if err != nil {
			return
		}
	}
}

// 流方向的操作码。
const (
	// streamKindSend 是上行流（客户端 → 校园网）。
	streamKindSend = 0x05
	// streamKindRecv 是下行流（校园网 → 客户端）。
	streamKindRecv = 0x06
)

// 帧长与协议层保持一致：4 字节操作码 + 48 字节 token + 8 字节 + 4 字节尾。
//
// 这里是另一份拷贝（internal/vpn/parse.go 里有一份同样的常量），
// 靠 internal/vpn 的 TestFakeFrameLengthsMatchProtocol 把两边钉在一起：
// 改一处不改另一处，那条测试会红。
const (
	StreamTokenLen = 48
	StreamFrameLen = 4 + StreamTokenLen + 8 + 4
	QueryFrameLen  = StreamFrameLen
)

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
