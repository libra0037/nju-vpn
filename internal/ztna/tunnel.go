package ztna

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libra0037/nju-vpn/internal/dial"
	"github.com/libra0037/nju-vpn/internal/l3"
)

const (
	// 心跳间隔。服务端在无心跳约 40 秒后断开，15 秒留了足够余量。
	heartbeatInterval = 15 * time.Second
	// 连续多少次心跳没回就把连接判死。15×3=45 秒，比服务端的
	// 40 秒宽松一点，先由服务端断开也是可以接受的。
	heartbeatMissLimit = 3
	// 扫描待鉴权流的间隔。
	authScanInterval = 250 * time.Millisecond
	// 一次最多发多少条鉴权请求。
	authBatchSize = 32
	// defaultHandshakeTimeout 是隧道握手阶段（TLS 加上之后的协议握手）的整体上限。
	//
	// 没有它的话，节点在完成 TCP/TLS 之后不再回帧，这一次读会永久阻塞：调用方
	// 的 ctx 取消不了它，守护进程的命令通道跟着卡死（stop / status 排不上队），
	// 而杀进程会跳过登出、把服务端的名额留着。10 秒比首包往返宽松得多，不会
	// 误伤慢链路。
	defaultHandshakeTimeout = 10 * time.Second
)

// tunnelConn 是一条 L3 隧道连接：TLS 之上跑本协议的帧。
type tunnelConn struct {
	node string
	conn net.Conn
	r    *bufio.Reader

	ep    *l3.Endpoint
	flows *flowTable
	table *resourceTable

	sid          string
	deviceID     string
	connectionID string
	signKey      []byte

	vipMu sync.RWMutex
	vip   net.IP

	writeMu sync.Mutex

	closeOnce sync.Once
	closeCh   chan struct{}
	closeErr  atomic.Pointer[error]

	authWake     chan struct{}
	heartbeatGap atomic.Int32

	logf func(format string, args ...any)
}

type tunnelOptions struct {
	Node     string
	Server   string // SNI 与 Host
	Dial     dial.DialFunc
	Table    *resourceTable
	Endpoint *l3.Endpoint
	SID      string
	DeviceID string
	SignKey  []byte
	Logf     func(format string, args ...any)
	// HandshakeTimeout 覆盖握手阶段的默认上限；0 表示用 defaultHandshakeTimeout。
	// 生产调用不设它，只有测试会传一个很短的值。
	HandshakeTimeout time.Duration
	// Pins 认节点证书的身份；nil 表示不校验（只有直接构造 tunnelOptions 的
	// 测试会这样）。
	Pins *nodePins
}

// dialTunnel 建立一条隧道连接并完成握手。返回时两个后台协程已经在跑。
func dialTunnel(ctx context.Context, opts tunnelOptions) (*tunnelConn, error) {
	raw, err := dialWithContext(ctx, opts.Dial, "tcp", opts.Node)
	if err != nil {
		return nil, fmt.Errorf("连接隧道节点 %s: %w", opts.Node, err)
	}
	tlsConfig := &tls.Config{
		ServerName:         opts.Server,
		InsecureSkipVerify: true, // 链与名称都不可用（自签、CN=sdp），身份由指纹认
	}
	if opts.Pins != nil {
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("节点 %s 没有出示证书", opts.Node)
			}
			return opts.Pins.verify(opts.Node, rawCerts[0])
		}
	}
	tlsConn := tls.Client(raw, tlsConfig)

	// 握手阶段整体带期限：TLS 与协议握手都算在内，成功后再清掉，否则会把
	// 之后的数据面读写一起拖死。
	timeout := opts.HandshakeTimeout
	if timeout <= 0 {
		timeout = defaultHandshakeTimeout
	}
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := tlsConn.SetDeadline(deadline); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("设置握手期限: %w", err)
	}
	// ctx 取消要能立刻打断正在进行的读：Go 没有别的办法叫醒一次阻塞的 Read。
	stopCancelWatch := watchCancel(ctx, tlsConn)
	defer stopCancelWatch()

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("隧道节点 TLS 握手: %w", err)
	}

	t := &tunnelConn{
		node:         opts.Node,
		conn:         tlsConn,
		ep:           opts.Endpoint,
		flows:        newFlowTable(),
		table:        opts.Table,
		sid:          opts.SID,
		deviceID:     opts.DeviceID,
		signKey:      opts.SignKey,
		connectionID: fmt.Sprintf("%X-%d", md5.Sum([]byte(opts.DeviceID)), time.Now().UnixMicro()),
		closeCh:      make(chan struct{}),
		authWake:     make(chan struct{}, 1),
		logf:         opts.Logf,
	}
	if t.logf == nil {
		t.logf = func(string, ...any) {}
	}

	br := bufio.NewReader(tlsConn)
	if _, err := tlsConn.Write(handshakeRequest(t.sid)); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("发送握手: %w", err)
	}
	res, err := readHandshake(br)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	// 握手已经结束：先停掉取消监听再清期限。反过来会留下一个窗口——监听器
	// 把刚清掉的期限又设成“现在”，数据面从第一包起就全废。
	stopCancelWatch()
	_ = tlsConn.SetDeadline(time.Time{})

	t.r = br
	t.setVIP(res.VIP)
	t.ep.SetLocalAddr(res.VIP)

	t.ep.SetUplink(t.Send)
	go t.readLoop()
	go t.heartbeatLoop()
	go t.authLoop()
	t.logf("隧道已建立: 节点 %s，地址 %s", t.node, t.vip.String())
	return t, nil
}

// watchCancel 让 ctx 的取消能打断一次阻塞中的读写。
//
// Go 没有别的办法叫醒已经在进行的 Read：把连接的期限提前到当前时刻，阻塞中
// 的调用会立刻以超时错误返回。返回的函数停止监听，可安全重复调用。
func watchCancel(ctx context.Context, conn net.Conn) func() {
	done := make(chan struct{})
	var once sync.Once
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-done:
		}
	}()
	return func() { once.Do(func() { close(done) }) }
}

// Done 在连接关闭时关闭，供重连逻辑等待。
func (t *tunnelConn) Done() <-chan struct{} { return t.closeCh }

// Err 返回连接断开的原因；主动关闭时返回 nil。
func (t *tunnelConn) Err() error {
	if p := t.closeErr.Load(); p != nil {
		return *p
	}
	return nil
}

func (t *tunnelConn) VIP() net.IP {
	t.vipMu.RLock()
	defer t.vipMu.RUnlock()
	return t.vip
}

func (t *tunnelConn) setVIP(ip net.IP) {
	t.vipMu.Lock()
	t.vip = append(net.IP(nil), ip...)
	t.vipMu.Unlock()
}

func (t *tunnelConn) write(buf []byte) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	_, err := t.conn.Write(buf)
	return err
}

// Send 是上行入口：承载层每来一个 IP 包都会调它。
//
// 它不做 I/O 之外的等待：命中资源表之后要么直接发出去，要么缓存首包
// 并唤醒鉴权协程。资源表没命中的包直接丢掉——发给服务端也会被丢。
func (t *tunnelConn) Send(pkt []byte) error {
	info, err := parsePacket(pkt)
	if err != nil {
		return err
	}
	proto := protoName(info.proto)
	appID, groupID, ok := t.table.match(info.dstIP, proto, info.dstPort)
	if !ok {
		return fmt.Errorf("目标不在资源表内: %s %s:%d", proto, info.dstIP, info.dstPort)
	}

	token, state := t.flows.sendState(info.key, appID, groupID)
	switch state {
	case flowFailed:
		return fmt.Errorf("该流鉴权失败: %s", info.key)
	case flowReady:
		// 有令牌，直接发。
	default:
		// 还没拿到令牌（或流刚建）：先缓存首包，让 authLoop 去申请。
		t.flows.cache(info.key, pkt)
		t.wakeAuth()
		return nil
	}
	frame, err := encodeDataFrame(token, pkt)
	if err != nil {
		return err
	}
	return t.write(frame)
}

func (t *tunnelConn) wakeAuth() {
	select {
	case t.authWake <- struct{}{}:
	default:
	}
}

func (t *tunnelConn) readLoop() {
	var stream []byte
	for {
		fr, err := readFrame(t.r)
		if err != nil {
			t.close(fmt.Errorf("隧道读取: %w", err))
			return
		}
		// 收到任何服务端帧都算对端还活着。本地写成功不算：对端静默消失
		// （NAT、防火墙、断电）时写入照样成功，只有“收到过东西”才说明
		// 链路真的还在，否则有上行流量时判死形同虚设。
		t.heartbeatGap.Store(0)
		switch fr.cmd {
		case cmdDataResp:
			stream = append(stream, fr.payload...)
			pkts, rest, err := splitPackets(stream)
			if err != nil {
				t.close(err)
				return
			}
			stream = rest
			for _, pkt := range pkts {
				t.ep.Deliver(pkt)
			}
		case cmdAuthResp:
			t.handleAuthResp(fr.status, fr.payload)
		case cmdVIPUpdate:
			t.handleVIPUpdate(fr.status, fr.payload)
		}
	}
}

// handleAuthResp 记录令牌并把该流缓存的包补发出去。
//
// 注意状态字节为 0 也可能是失败：会话失效时服务端正是这么回的。
func (t *tunnelConn) handleAuthResp(status byte, payload []byte) {
	var resp struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			ConnectToken  string `json:"connectToken"`
			ConntrackHash uint64 `json:"conntrackHash"`
		} `json:"data"`
	}
	if err := json.Unmarshal(payload, &resp); err != nil {
		t.logf("鉴权响应无法解析: %v", err)
		return
	}
	if status != 0 || resp.Code != 0 {
		t.logf("鉴权被拒: status=%d code=%d message=%s", status, resp.Code, resp.Message)
		t.flows.completeAuth(resp.Data.ConntrackHash, "", fmt.Errorf("鉴权被拒（%d）", resp.Code))
		return
	}
	_, pending := t.flows.completeAuth(resp.Data.ConntrackHash, resp.Data.ConnectToken, nil)
	if len(pending) == 0 {
		return
	}
	frame, err := encodeDataFrame(resp.Data.ConnectToken, pending...)
	if err != nil {
		t.logf("补发首包失败: %v", err)
		return
	}
	if err := t.write(frame); err != nil {
		t.close(err)
	}
}

func (t *tunnelConn) handleVIPUpdate(status byte, payload []byte) {
	if status != 0 {
		return
	}
	// 载荷是地址列表；承载层只改写 IPv4，取第一个 IPv4 就是它要的那个。
	for _, ip := range parseVIPListPayload(payload) {
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		if cur := t.VIP(); cur != nil && cur.Equal(v4) {
			return
		}
		t.setVIP(v4)
		// 先让承载层跟着切，再记自己的值：顺序反了会出现“映射还在用旧地址”
		// 的窗口，那段时间上下行都会被丢。
		t.ep.SetLocalAddr(v4)
		t.logf("服务端下发地址: %s（数据面已跟着切）", v4)
		return
	}
}

func (t *tunnelConn) heartbeatLoop() {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := t.write(encodeHeartbeat()); err != nil {
				t.close(err)
				return
			}
			// 判死放在自增之后：计数才等于"已经连续几次没回应"。放在前面
			// 会让实际判死周期变成 4 个 tick，与常量注释里的 15×3=45 秒对不上。
			t.heartbeatGap.Add(1)
			if t.heartbeatGap.Load() >= heartbeatMissLimit {
				t.close(fmt.Errorf("心跳连续 %d 次没有回应", heartbeatMissLimit))
				return
			}
		case <-t.closeCh:
			return
		}
	}
}

func (t *tunnelConn) authLoop() {
	ticker := time.NewTicker(authScanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-t.authWake:
			if !t.dispatchAuth() {
				return
			}
		case <-ticker.C:
			// 回收超时的流。挂在 250ms 的扫描上而不是 15 秒的心跳上：
			// flowAuthTimeout 是 8 秒，响应丢失的流最坏要等一个心跳周期才
			// 被放掉，表现为偶发的一次"连接卡住"。
			t.flows.expire(time.Now())
			if !t.dispatchAuth() {
				return
			}
		case <-t.closeCh:
			return
		}
	}
}

func (t *tunnelConn) dispatchAuth() bool {
	for _, f := range t.flows.pendingAuth(authBatchSize) {
		if err := t.sendAuthRequest(f); err != nil {
			t.close(err)
			return false
		}
		t.flows.markAuthSent(f.key)
	}
	return true
}

func (t *tunnelConn) sendAuthRequest(f *flow) error {
	body, err := t.buildAuthRequest(f)
	if err != nil {
		return err
	}
	frame, err := encodeAuthRequest(body)
	if err != nil {
		return err
	}
	return t.write(frame)
}

type authIPJSON struct {
	Atype    int    `json:"atype"`
	Protocol int    `json:"protocol"`
	DestAddr string `json:"destAddr"`
	DestPort int    `json:"destPort"`
	SrcAddr  string `json:"srcAddr"`
	SrcPort  int    `json:"srcPort"`
}

type processJSON struct {
	Name             string `json:"name"`
	DigitalSignature string `json:"digital_signature"`
	Platform         string `json:"platform"`
	Fingerprint      string `json:"fingerprint"`
	Description      string `json:"description"`
	Path             string `json:"path"`
	Version          string `json:"version"`
	SecurityEnv      string `json:"security_env"`
}

type envJSON struct {
	Application struct {
		Runtime struct {
			Process        processJSON `json:"process"`
			ProcessTrusted string      `json:"process_trusted"`
		} `json:"runtime"`
	} `json:"application"`
}

type authRequestJSON struct {
	Sid           string     `json:"sid"`
	AppID         string     `json:"appId"`
	URL           string     `json:"url"`
	DeviceID      string     `json:"deviceId"`
	ConnectionID  string     `json:"connectionId"`
	Env           envJSON    `json:"env"`
	ConntrackHash uint64     `json:"conntrackHash"`
	Lang          string     `json:"lang"`
	IP            authIPJSON `json:"ip"`
	ProcHash      string     `json:"procHash"`
}

// buildAuthRequest 组装逐流鉴权请求。
//
// 签名字段单独拼在末尾：签名覆盖的是不含它的那段 JSON 字节。
func (t *tunnelConn) buildAuthRequest(f *flow) ([]byte, error) {
	ipProto := int(protoTCP)
	switch f.key.proto {
	case protoUDP:
		ipProto = protoUDP
	case protoICMP:
		ipProto = protoICMP
	}
	vip := t.VIP()
	procPath := "/usr/bin/njuvpn"
	sum := sha256.Sum256([]byte(procPath))

	req := authRequestJSON{
		Sid:           t.sid,
		AppID:         f.appID,
		URL:           fmt.Sprintf("%s:%s:%d", protoName(f.key.proto), f.key.dst, f.key.dport),
		DeviceID:      t.deviceID,
		ConnectionID:  t.connectionID,
		ConntrackHash: f.authID,
		Lang:          "en-US",
		IP: authIPJSON{
			Atype: 0x0800, Protocol: ipProto,
			DestAddr: f.key.dst, DestPort: int(f.key.dport),
			SrcAddr: f.key.src, SrcPort: int(f.key.sport),
		},
		ProcHash: fmt.Sprintf("%X", sum),
	}
	req.Env.Application.Runtime.Process = processJSON{
		Name: clientIdentity, DigitalSignature: "TrustAppClosed", Platform: "Linux",
		Fingerprint: fmt.Sprintf("%X", sum), Description: "TrustAppClosed",
		Path: procPath, Version: "TrustAppClosed", SecurityEnv: "normal",
	}
	req.Env.Application.Runtime.ProcessTrusted = "TRUSTED"
	_ = vip

	unsigned, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, t.signKey)
	mac.Write(unsigned)
	sig := hex.EncodeToString(mac.Sum(nil))
	return append([]byte(string(unsigned[:len(unsigned)-1])), []byte(fmt.Sprintf(",%q:%q}", "xRequestSig", upperHex(sig)))...), nil
}

func upperHex(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'f' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}

func (t *tunnelConn) close(err error) {
	t.closeOnce.Do(func() {
		if err != nil {
			t.closeErr.Store(&err)
		}
		close(t.closeCh)
		t.ep.ClearUplink()
		_ = t.conn.Close()
		if err != nil {
			t.logf("隧道断开: %v", err)
		}
	})
}

// Close 供重连逻辑使用：关掉连接并注销上行回调。
func (t *tunnelConn) Close() error {
	t.close(nil)
	return nil
}
