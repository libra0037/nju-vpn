// Package ztnatest 提供一个离线的假服务端，供协议层与承载层的测试使用。
//
// 它自己实现服务端那一侧的报文格式，不引用被测代码——两边独立写同一份
// 协议，其中一边写错时测试才会失败（共用一份编解码就等于自证）。
//
// 一个监听端口同时承担两个角色：控制面（HTTPS）与隧道节点。TLS 建立之后按
// 第一个字节分流——HTTP 请求以方法名开头，隧道以 0x05 开头。
package ztnatest

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// App 是资源表里的一条资源。
type App struct {
	ID          string
	NodeGroupID string
	AccessModel string
	// Protocol 是 tcp / udp / all。
	Protocol string
	// Host 支持单个地址、CIDR 与 "起-止" 三种写法。
	Host string
	Port string
}

// Options 是假服务端的行为参数。
type Options struct {
	Username string
	Password string

	// RequireSMS 要求短信二次验证，VerifyCode 是唯一正确的验证码。
	// LegacySMSForm 让口令登录直接返回短信这一步（旧形态：没有 authId，
	// 提交验证码时走表单编码）。
	RequireSMS    bool
	VerifyCode    string
	LegacySMSForm bool
	Phone         string

	// VIP 是隧道分配的地址。
	VIP string
	// SelfID 是本机在授信终端列表里的 id，Trusted 是初始已授信的 id 列表。
	SelfID     string
	Trusted    []string
	TrustLimit int

	// Apps 是资源表里发布的能力，留空则给一条覆盖 10.0.0.0/8 的全协议规则。
	Apps []App
	// Nodes 是资源表里发布的隧道节点地址，留空则用本机监听地址。
	Nodes []string
}

// Server 是假服务端。
type Server struct {
	opts Options
	ln   net.Listener
	addr string
	tls  *tls.Config
	http *http.ServeMux
	rsa  *rsa.PrivateKey

	mu          sync.Mutex
	smsVerified bool
	trusted     []string
	tunnel      net.Conn
	uplink      [][]byte
	sid         string
	logoutCount int

	smsSends     atomic.Int32
	tunnelCount  atomic.Int32
	authRequests atomic.Int32
	heartbeats   atomic.Int32
}

// New 启动假服务端。
func New(opts Options) (*Server, error) {
	if opts.VIP == "" {
		opts.VIP = "172.16.0.9"
	}
	if opts.SelfID == "" {
		opts.SelfID = "self-1"
	}
	if opts.TrustLimit == 0 {
		opts.TrustLimit = 3
	}
	if len(opts.Apps) == 0 {
		opts.Apps = []App{{ID: "app-l3", NodeGroupID: "ng1", AccessModel: "L3VPN", Protocol: "all", Host: "10.0.0.0/8", Port: "0"}}
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	cert, err := selfSignedCert()
	if err != nil {
		return nil, err
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &Server{
		opts:    opts,
		ln:      ln,
		addr:    ln.Addr().String(),
		rsa:     rsaKey,
		trusted: append([]string(nil), opts.Trusted...),
		sid:     "sid-cookie-value",
		tls: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
	}
	s.http = s.routes()
	go s.serve()
	return s, nil
}

// Addr 返回监听地址（host:port）。控制面与隧道节点都是它。
func (s *Server) Addr() string { return s.addr }

// Dial 是一个拨号函数（与网络层 dial.DialFunc 同形）：不管目标写的是什么，
// 都连到假服务端。目标与预期不符时报错，接线错误因此会立刻暴露。
func (s *Server) Dial(network, addr string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("假服务端只支持 tcp，收到 %q", network)
	}
	if addr != s.addr {
		return nil, fmt.Errorf("拨号目标 %q 与假服务端 %q 不符", addr, s.addr)
	}
	return net.Dial("tcp", s.addr)
}

// Close 停止服务。
func (s *Server) Close() error { return s.ln.Close() }

// Trusted 返回当前授信终端 id 列表。
func (s *Server) Trusted() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.trusted...)
}

// LogoutCount 返回控制面收到的登出次数。
func (s *Server) LogoutCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logoutCount
}

// Uplink 返回隧道里收到的上行 IP 包。
func (s *Server) Uplink() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]byte, 0, len(s.uplink))
	for _, p := range s.uplink {
		out = append(out, append([]byte(nil), p...))
	}
	return out
}

// AuthRequests 返回收到的逐流鉴权请求数。
func (s *Server) AuthRequests() int { return int(s.authRequests.Load()) }

// Heartbeats 返回收到的心跳数。
func (s *Server) Heartbeats() int { return int(s.heartbeats.Load()) }

// SMSSends 返回收到的"发送短信"请求数。
func (s *Server) SMSSends() int { return int(s.smsSends.Load()) }

// Tunnels 返回建立过的隧道连接数。
func (s *Server) Tunnels() int { return int(s.tunnelCount.Load()) }

// SendDownlink 往当前隧道连接里塞一个下行 IP 包。
func (s *Server) SendDownlink(pkt []byte) error {
	s.mu.Lock()
	conn := s.tunnel
	s.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("还没有隧道连接")
	}
	frame := []byte{0x05, 0x94}
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(pkt)))
	_, err := conn.Write(append(frame, pkt...))
	return err
}

// CloseTunnel 掐断当前隧道连接，用来测重连。
func (s *Server) CloseTunnel() {
	s.mu.Lock()
	conn := s.tunnel
	s.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
}

func selfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "njuvpn-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"vpn.test", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
}

// serve 接受连接：TLS 握手之后按第一个字节把控制面与隧道分开。
func (s *Server) serve() {
	for {
		raw, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(raw)
	}
}

func (s *Server) handleConn(raw net.Conn) {
	tlsConn := tls.Server(raw, s.tls)
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return
	}
	br := bufio.NewReader(tlsConn)
	first, err := br.Peek(1)
	if err != nil {
		tlsConn.Close()
		return
	}
	if first[0] == 0x05 {
		s.handleTunnel(tlsConn, br)
		return
	}
	conn := &bufferedConn{Conn: tlsConn, r: br}
	http.Serve(&oneShotListener{conn: conn}, s.http)
}

// bufferedConn 让 bufio 预读的字节不丢失。
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// oneShotListener 把一条已经建好的连接交给 http.Serve：Accept 一次之后就
// 报告监听已关闭。http.Serve 会返回，但它已经派出去的那条连接照常处理完。
type oneShotListener struct {
	conn net.Conn
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	if l.conn == nil {
		return nil, net.ErrClosed
	}
	c := l.conn
	l.conn = nil
	return c, nil
}

func (l *oneShotListener) Close() error {
	if l.conn != nil {
		return l.conn.Close()
	}
	return nil
}

func (l *oneShotListener) Addr() net.Addr { return dummyAddr{} }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "fake" }
func (dummyAddr) String() string  { return "fake" }

// routes 是控制面的路由表。
func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/public/manifest", func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, 0, "", map[string]any{
			"server":      "portal-test",
			"trustDevice": map[string]any{"enable": true},
		})
	})
	mux.HandleFunc("/passport/v1/public/authConfig", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: s.sid, Path: "/"})
		writeEnvelope(w, 0, "", map[string]any{
			"csrfToken":      "csrf-token",
			"antiReplayRand": "rand-1",
			"pubKey":         hex.EncodeToString(s.rsa.N.Bytes()),
			"pubKeyExp":      "65537",
			"isLogin":        0,
			"authServerInfoList": []map[string]any{
				{"authType": "auth/psw", "loginDomain": "test"},
			},
		})
	})
	mux.HandleFunc("/passport/v1/auth/psw", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: s.sid, Path: "/"})
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := readJSON(r, &body); err != nil {
			writeEnvelope(w, 400, err.Error(), nil)
			return
		}
		plain, err := s.decryptPassword(body.Password)
		if err != nil {
			writeEnvelope(w, 400, "口令解密失败: "+err.Error(), nil)
			return
		}
		// 客户端送来的明文是"口令_反重放随机数"。
		if plain != s.opts.Password+"_"+"rand-1" {
			// 与真实服务端一致：口令错误回的是 75500000（HTTP 200 + 该错误码）。
			writeEnvelope(w, 75500000, "The username or password is incorrect. You still have 9 attempts left", nil)
			return
		}
		if want := s.opts.Username + "@test"; body.Username != want {
			writeEnvelope(w, 400, "用户名错误: "+body.Username, nil)
			return
		}
		next := "auth/authCheck"
		if s.opts.LegacySMSForm {
			next = "auth/sms"
		}
		writeEnvelope(w, 0, "", map[string]any{"ticket": "ticket-1", "nextService": next})
	})
	mux.HandleFunc("/controller/v1/public/reportEnv", func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, 0, "", map[string]any{})
	})
	mux.HandleFunc("/passport/v1/auth/authCheck", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		done := s.smsVerified
		s.mu.Unlock()
		if s.opts.RequireSMS && !done {
			writeEnvelope(w, 0, "", map[string]any{
				"nextService": "auth/sms",
				"nextServiceList": []map[string]any{
					{"authType": "auth/sms", "authId": "auth-1"},
				},
			})
			return
		}
		writeEnvelope(w, 0, "", map[string]any{})
	})
	mux.HandleFunc("/passport/v1/public/phoneNumber", func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, 0, "", map[string]any{"phoneNumber": s.opts.Phone})
	})
	mux.HandleFunc("/passport/v1/auth/sms", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("action") {
		case "sendsms":
			s.smsSends.Add(1)
			writeEnvelope(w, 0, "验证码已发送", map[string]any{"tips": "验证码已发送"})
		case "checkcode":
			code, err := requestCode(r)
			if err != nil {
				writeEnvelope(w, 400, err.Error(), nil)
				return
			}
			if code != s.opts.VerifyCode {
				writeEnvelope(w, 75500005, "验证码错误", nil)
				return
			}
			s.mu.Lock()
			s.smsVerified = true
			s.mu.Unlock()
			writeEnvelope(w, 0, "", map[string]any{})
		default:
			writeEnvelope(w, 400, "未知的短信动作", nil)
		}
	})
	mux.HandleFunc("/passport/v1/user/onlineInfo", func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, 0, "", map[string]any{"username": s.opts.Username, "isOnline": true})
	})
	mux.HandleFunc("/controller/v1/user/clientResource", func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, 0, "", s.resourceTable())
	})
	mux.HandleFunc("/passport/v1/security/queryDevice", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		trusted := append([]string(nil), s.trusted...)
		s.mu.Unlock()
		selfTrusted := false
		devices := make([]map[string]any, 0, len(trusted))
		for _, id := range trusted {
			if id == s.opts.SelfID {
				selfTrusted = true
			}
			devices = append(devices, map[string]any{"id": id, "deviceName": id, "os": "linux"})
		}
		writeEnvelope(w, 0, "", map[string]any{
			"selfId":                  s.opts.SelfID,
			"deviceTrusted":           selfTrusted,
			"currentTrustDeviceCount": len(trusted),
			"maxDeviceCount":          s.opts.TrustLimit,
			"trustDeviceConfig":       map[string]any{"enable": true},
			"data":                    devices,
		})
	})
	mux.HandleFunc("/passport/v1/security/trustDevice", func(w http.ResponseWriter, r *http.Request) {
		s.trust(w, r, true)
	})
	mux.HandleFunc("/passport/v1/security/untrustDevice", func(w http.ResponseWriter, r *http.Request) {
		s.trust(w, r, false)
	})
	mux.HandleFunc("/passport/v1/security/logoutDevice", func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, 0, "", map[string]any{})
	})
	mux.HandleFunc("/passport/v1/user/logout", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.logoutCount++
		s.mu.Unlock()
		writeEnvelope(w, 0, "", map[string]any{})
	})
	return mux
}

// trust 处理授信终端的增删。服务端只接受 idList：用别的字段名会被拒。
func (s *Server) trust(w http.ResponseWriter, r *http.Request, add bool) {
	var body struct {
		IDList []string `json:"idList"`
	}
	if err := readJSON(r, &body); err != nil {
		writeEnvelope(w, 400, err.Error(), nil)
		return
	}
	if len(body.IDList) == 0 {
		writeEnvelope(w, 400, "缺少 idList", nil)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range body.IDList {
		if add {
			dup := false
			for _, t := range s.trusted {
				if t == id {
					dup = true
				}
			}
			if !dup {
				s.trusted = append(s.trusted, id)
			}
			continue
		}
		kept := s.trusted[:0]
		for _, t := range s.trusted {
			if t != id {
				kept = append(kept, t)
			}
		}
		s.trusted = kept
	}
	writeEnvelope(w, 0, "", map[string]any{})
}

// resourceTable 组装资源表响应。
func (s *Server) resourceTable() map[string]any {
	apps := make([]map[string]any, 0, len(s.opts.Apps))
	for _, a := range s.opts.Apps {
		apps = append(apps, map[string]any{
			"id":          a.ID,
			"nodeGroupId": a.NodeGroupID,
			"accessModel": a.AccessModel,
			"addressList": []map[string]any{{"protocol": a.Protocol, "port": a.Port, "host": a.Host}},
		})
	}
	nodes := s.opts.Nodes
	if len(nodes) == 0 {
		nodes = []string{s.addr}
	}
	infos := make([]map[string]any, 0, len(nodes))
	for _, n := range nodes {
		infos = append(infos, map[string]any{"address": n, "type": "wan"})
	}
	return map[string]any{
		"appList": map[string]any{
			"data": map[string]any{
				"appInfo": []map[string]any{{"apps": apps}},
				"config": map[string]any{
					"nodeGroupConf": map[string]any{
						"majorNodeGroup": map[string]any{"id": "ng1"},
						"nodeGroupList": []map[string]any{
							{"id": "ng1", "addressInfo": infos},
						},
					},
				},
			},
		},
		"sdpPolicy": map[string]any{
			"data": map[string]any{
				"clientOption": map[string]any{
					"dnsOption": map[string]any{"firstDNS": "10.0.0.53"},
				},
			},
		},
	}
}

// decryptPassword 用私钥还原口令，验证客户端的加密实现。
func (s *Server) decryptPassword(hexCipher string) (string, error) {
	raw, err := hex.DecodeString(hexCipher)
	if err != nil {
		return "", fmt.Errorf("密文不是十六进制: %w", err)
	}
	size := s.rsa.Size()
	if len(raw)%size != 0 {
		return "", fmt.Errorf("密文长度 %d 不是密钥长度 %d 的整数倍", len(raw), size)
	}
	var out []byte
	for i := 0; i+size <= len(raw); i += size {
		//lint:ignore SA1019 假服务端要复现服务端的 PKCS#1 v1.5 解密
		chunk, err := rsa.DecryptPKCS1v15(rand.Reader, s.rsa, raw[i:i+size])
		if err != nil {
			return "", err
		}
		out = append(out, chunk...)
	}
	return string(out), nil
}

// requestCode 从请求体里取出验证码。
//
// 客户端把表单编码的请求体也带上 JSON 的 Content-Type（真实服务端两种都收），
// 所以这里按内容判断：先按 JSON 解，解不出来再按表单解。
func requestCode(r *http.Request) (string, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return "", err
	}
	var parsed struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(body, &parsed); err == nil {
		return parsed.Code, nil
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return "", err
	}
	if code := form.Get("code"); code != "" {
		return code, nil
	}
	return "", fmt.Errorf("请求体里没有验证码")
}

func readJSON(r *http.Request, v any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("请求体不是合法 JSON: %w", err)
	}
	return nil
}

func writeEnvelope(w http.ResponseWriter, code int, message string, data any) {
	if data == nil {
		data = map[string]any{}
	}
	w.Header().Set("Content-Type", "application/json;charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"code": code, "message": message, "data": data})
}

// 隧道层的常量。与客户端侧的编解码是同一份协议的两次独立实现。
const (
	verHandshake    = 0x01
	verMethodOk     = 0xD0
	verEnvelope     = 0x53
	verAuthReq      = 0x13
	verAuthResp     = 0x93
	verDataReq      = 0x14
	verDataResp     = 0x94
	verHeartbeatReq = 0x15
	verHeartbeatRes = 0x95
)

// handleTunnel 处理一条隧道连接。
func (s *Server) handleTunnel(conn net.Conn, r *bufio.Reader) {
	defer conn.Close()
	s.tunnelCount.Add(1)

	head := make([]byte, 5)
	if _, err := io.ReadFull(r, head); err != nil {
		return
	}
	if head[0] != 0x05 || head[1] != verHandshake || head[2] != verMethodOk || head[3] != verEnvelope {
		return
	}
	payload, err := readEnvelopePayload(r)
	if err != nil {
		return
	}
	var hello struct {
		SID string `json:"sid"`
	}
	if err := json.Unmarshal(payload, &hello); err != nil || hello.SID != s.sid {
		return
	}
	// 握手请求的尾巴：版本、方法、保留位、地址类型与 6 字节地址体。
	tail := make([]byte, 10)
	if _, err := io.ReadFull(r, tail); err != nil {
		return
	}

	// 响应：方法响应 + 一个信封 + 虚拟地址。
	resp := []byte{0x05, verMethodOk, verEnvelope, 0x00}
	body, err := json.Marshal(map[string]any{"code": 0})
	if err != nil {
		return
	}
	resp = binary.BigEndian.AppendUint16(resp, uint16(len(body)))
	resp = append(resp, body...)
	resp = append(resp, 0x05, 0x00, 0x00, 0x01)
	vip := net.ParseIP(s.opts.VIP).To4()
	if vip == nil {
		return
	}
	resp = append(resp, vip...)
	resp = append(resp, 0x00, 0x00)
	if _, err := conn.Write(resp); err != nil {
		return
	}

	s.mu.Lock()
	s.tunnel = conn
	s.mu.Unlock()

	for {
		frame, err := readServerFrame(r)
		if err != nil {
			return
		}
		switch frame.cmd {
		case verHeartbeatReq:
			s.heartbeats.Add(1)
			if _, err := conn.Write([]byte{0x05, verHeartbeatRes, 0x00, 0x00}); err != nil {
				return
			}
		case verAuthReq:
			s.authRequests.Add(1)
			var req struct {
				ConntrackHash uint64 `json:"conntrackHash"`
			}
			if err := json.Unmarshal(frame.payload, &req); err != nil {
				return
			}
			answer, err := json.Marshal(map[string]any{
				"code": 0,
				"data": map[string]any{"connectToken": "tok-1", "conntrackHash": req.ConntrackHash},
			})
			if err != nil {
				return
			}
			out := []byte{0x05, verAuthResp, 0x00}
			out = binary.BigEndian.AppendUint16(out, uint16(len(answer)))
			if _, err := conn.Write(append(out, answer...)); err != nil {
				return
			}
		case verDataReq:
			pkts, err := parseClientDataFrame(frame.payload)
			if err != nil {
				return
			}
			s.mu.Lock()
			s.uplink = append(s.uplink, pkts...)
			s.mu.Unlock()
		default:
			return
		}
	}
}

// readEnvelopePayload 读一个 53 信封的正文。
func readEnvelopePayload(r *bufio.Reader) ([]byte, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(head))
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// serverFrame 是服务端视角下的一帧。
type serverFrame struct {
	cmd     byte
	payload []byte
}

func readServerFrame(r *bufio.Reader) (serverFrame, error) {
	var f serverFrame
	head := make([]byte, 2)
	if _, err := io.ReadFull(r, head); err != nil {
		return f, err
	}
	if head[0] != 0x05 {
		return f, fmt.Errorf("帧版本不是 0x05: %02x", head[0])
	}
	f.cmd = head[1]
	switch f.cmd {
	case verHeartbeatReq:
		return f, nil
	case verAuthReq:
		var l [2]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return f, err
		}
		f.payload = make([]byte, int(binary.BigEndian.Uint16(l[:])))
		_, err := io.ReadFull(r, f.payload)
		return f, err
	case verDataReq:
		// 数据帧：tokenLen | token | 00 00 | count | (len | pkt)*
		var lenByte [1]byte
		if _, err := io.ReadFull(r, lenByte[:]); err != nil {
			return f, err
		}
		tokenLen := int(lenByte[0])
		mid := make([]byte, tokenLen+3)
		if _, err := io.ReadFull(r, mid); err != nil {
			return f, err
		}
		count := int(mid[len(mid)-1])
		f.payload = append(f.payload, lenByte[:]...)
		f.payload = append(f.payload, mid...)
		for i := 0; i < count; i++ {
			var pktLen [2]byte
			if _, err := io.ReadFull(r, pktLen[:]); err != nil {
				return f, err
			}
			pkt := make([]byte, int(binary.BigEndian.Uint16(pktLen[:])))
			if _, err := io.ReadFull(r, pkt); err != nil {
				return f, err
			}
			f.payload = append(f.payload, pktLen[:]...)
			f.payload = append(f.payload, pkt...)
		}
		return f, nil
	default:
		return f, fmt.Errorf("未知的隧道帧: %02x", f.cmd)
	}
}

// parseClientDataFrame 解析 14 数据帧的正文，取出其中的 IP 包。
func parseClientDataFrame(payload []byte) ([][]byte, error) {
	if len(payload) < 4 {
		return nil, fmt.Errorf("数据帧过短")
	}
	// payload = tokenLen | token | 00 00 | count | (len | pkt)*
	tokenLen := int(payload[0])
	at := 1 + tokenLen
	if len(payload) < at+3 {
		return nil, fmt.Errorf("数据帧头部不完整")
	}
	count := int(payload[at+2])
	at += 3
	var out [][]byte
	for i := 0; i < count; i++ {
		if len(payload) < at+2 {
			return nil, fmt.Errorf("数据帧第 %d 个包的长度缺失", i)
		}
		n := int(binary.BigEndian.Uint16(payload[at:]))
		at += 2
		if len(payload) < at+n {
			return nil, fmt.Errorf("数据帧第 %d 个包不完整", i)
		}
		out = append(out, append([]byte(nil), payload[at:at+n]...))
		at += n
	}
	return out, nil
}
