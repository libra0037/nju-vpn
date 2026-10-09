package ztna

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libra0037/nju-vpn/internal/dial"
	"github.com/libra0037/nju-vpn/internal/l3"
	"github.com/libra0037/nju-vpn/internal/packetlog"
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

	// maxStreamBytes 是下行累计缓冲的上限。
	//
	// 单帧包长上限是 65535，而按声明长度切包时切剩的半个包要等下一帧补齐：
	// 对端只要每帧都"比声明的少一字节"，这个缓冲就会一直长下去（心跳判死前
	// 有 45 秒窗口，速率受 TCP 发送窗口限制）。给个上限，超过即按协议错误断开。
	maxStreamBytes       = 4 * 0xFFFF
	dataWriteTimeout     = 5 * time.Second
	authRetryLogInterval = 10 * time.Second
)

// tunnelConn 是一条 L3 隧道连接：TLS 之上跑本协议的帧。
type tunnelConn struct {
	node string
	conn net.Conn
	raw  net.Conn
	r    *bufio.Reader

	ep    *l3.Endpoint
	mtu   int
	flows *flowTable
	table *resourceTable

	sid          string
	deviceID     string
	connectionID string
	signKey      []byte

	initialAddr net.IP // 仅在发布前保存握手结果；启动后地址的权威为 Endpoint。
	unregister  func()
	workers     sync.WaitGroup

	writeMu sync.Mutex

	closeOnce sync.Once
	closeCh   chan struct{}
	closeErr  atomic.Pointer[error]

	authWake       chan struct{}
	heartbeatGap   atomic.Int32
	rejectMu       sync.Mutex
	rejected       RejectionCounts
	rejectLogAt    time.Time
	authRetryLogAt atomic.Int64

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
	Pins             *nodeSPKIPins
	MTU              int
}

// dialTunnel 只完成握手，返回尚未注册回调、尚未启动任务的连接。
func dialTunnel(ctx context.Context, opts tunnelOptions) (*tunnelConn, error) {
	// 重连直接拨号时，TLS 与协议握手仍共用原来的整体期限。
	ctx, cancel := context.WithTimeout(ctx, opts.handshakeTimeout())
	defer cancel()
	conn, err := dialNodeTLS(ctx, opts)
	if err != nil {
		return nil, err
	}
	return handshakeTunnel(ctx, opts, conn)
}

func (opts tunnelOptions) handshakeTimeout() time.Duration {
	if opts.HandshakeTimeout > 0 {
		return opts.HandshakeTimeout
	}
	return defaultHandshakeTimeout
}

// dialNodeTLS 不发送 SID；选点只证明 TLS 可用且身份在配置白名单内。
// 成功时交出可继续做协议握手的连接，失败时关闭底层连接。
func dialNodeTLS(ctx context.Context, opts tunnelOptions) (*tls.Conn, error) {
	if opts.Pins == nil || len(opts.Pins.allowed) == 0 {
		return nil, ErrNodeUntrusted
	}
	ctx, cancel := context.WithTimeout(ctx, opts.handshakeTimeout())
	defer cancel()
	raw, err := dialWithContext(ctx, opts.Dial, "tcp", opts.Node)
	if err != nil {
		return nil, dial.Wrap("连接隧道节点", err)
	}
	tlsConfig := &tls.Config{
		ServerName:         opts.Server,
		InsecureSkipVerify: true, // 链与名称都不可用（自签、CN=sdp），身份由指纹认
		MinVersion:         tls.VersionTLS12,
	}
	tlsConfig.VerifyConnection = opts.Pins.verify
	tlsConn := tls.Client(raw, tlsConfig)

	deadline, _ := ctx.Deadline()
	if err := tlsConn.SetDeadline(deadline); err != nil {
		_ = raw.Close()
		return nil, dial.Wrap("设置节点 TLS 期限", err)
	}
	// 标准库 HandshakeContext 负责取消 TLS 握手，无需另设取消监听。
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, dial.Wrap("隧道节点 TLS 握手", errors.Join(ErrNodeTLS, err))
	}
	if err := ctx.Err(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		_ = raw.Close()
		return nil, dial.Wrap("清除节点 TLS 期限", err)
	}
	return tlsConn, nil
}

// handshakeTunnel 接管已验证的 TLS 连接；失败时关闭，成功时交给 tunnelConn。
func handshakeTunnel(ctx context.Context, opts tunnelOptions, tlsConn *tls.Conn) (*tunnelConn, error) {
	ctx, cancel := context.WithTimeout(ctx, opts.handshakeTimeout())
	defer cancel()
	raw := tlsConn.NetConn()
	deadline, _ := ctx.Deadline()
	if err := tlsConn.SetDeadline(deadline); err != nil {
		_ = raw.Close()
		return nil, dial.Wrap("设置协议握手期限", err)
	}
	stopCancelWatch := watchCancel(ctx, tlsConn)
	defer stopCancelWatch()

	t := &tunnelConn{
		node:         opts.Node,
		mtu:          opts.MTU,
		conn:         tlsConn,
		raw:          raw,
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
	request, err := handshakeRequest(t.sid)
	if err != nil {
		raw.Close()
		return nil, err
	}
	if _, err := tlsConn.Write(request); err != nil {
		_ = raw.Close()
		return nil, dial.Wrap("发送握手", err)
	}
	res, err := readHandshake(br)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	// 握手已经结束：先停掉取消监听再清期限。反过来会留下一个窗口——监听器
	// 把刚清掉的期限又设成“现在”，数据面从第一包起就全废。
	stopCancelWatch()
	if err := ctx.Err(); err != nil {
		raw.Close()
		return nil, err
	}
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		raw.Close()
		return nil, dial.Wrap("清除握手期限", err)
	}

	t.r = br
	t.initialAddr = res.VIP
	return t, nil
}

// 调用方在会话锁内接纳连接后启动，关闭与接纳因此不会交错。
func (t *tunnelConn) start() {
	t.ep.SetLocalAddr(t.initialAddr)
	t.initialAddr = nil
	t.unregister = t.ep.SetUplink(t.Send)
	t.workers.Go(t.readLoop)
	t.workers.Go(t.heartbeatLoop)
	t.workers.Go(t.authLoop)
}

// watchCancel 让 ctx 的取消能打断一次阻塞中的读写。
//
// Go 没有别的办法叫醒已经在进行的 Read：把连接的期限提前到当前时刻，阻塞中
// 的调用会立刻以超时错误返回。返回的函数停止监听，可安全重复调用。
func watchCancel(ctx context.Context, conn net.Conn) func() {
	done := make(chan struct{})
	joined := make(chan struct{})
	var once sync.Once
	go func() {
		defer close(joined)
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-done:
		}
	}()
	return func() { once.Do(func() { close(done) }); <-joined }
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
	return t.ep.LocalAddr()
}

func (t *tunnelConn) write(buf []byte) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	select {
	case <-t.closeCh:
		return net.ErrClosed
	default:
	}
	if err := t.conn.SetWriteDeadline(time.Now().Add(dataWriteTimeout)); err != nil {
		err = dial.Wrap("设置隧道写期限", err)
		t.close(err)
		return err
	}
	n, err := t.conn.Write(buf)
	if err == nil && n != len(buf) {
		err = io.ErrShortWrite
	}
	if err != nil {
		t.close(dial.Wrap("隧道写入", err))
	}
	return dial.Wrap("隧道写入", err)
}

// Send 是上行入口：承载层每来一个 IP 包都会调它。
//
// 它不做 I/O 之外的等待：命中资源表之后要么直接发出去，要么缓存首包
// 并唤醒鉴权协程。资源表没命中的包直接丢掉——发给服务端也会被丢。
func (t *tunnelConn) Send(pkt []byte) (resultErr error) {
	defer func() {
		if resultErr != nil {
			t.recordRejection(resultErr)
		}
	}()
	info, err := parsePacket(pkt)
	if err != nil {
		if info.fragmented() {
			t.flows.rejectFragment(info.fragment)
		}
		return err
	}
	if len(pkt) > t.mtu {
		if info.fragmented() {
			t.flows.rejectFragment(info.fragment)
		}
		return ErrPacketTooLarge
	}
	var appID string
	if info.offset == 0 {
		var ok bool
		grant, matched := t.table.matchIP(netip.AddrFrom4(info.key.dst), info.proto, info.dstPort)
		appID, ok = grant.appID, matched
		if !ok {
			if info.fragmented() {
				t.flows.rejectFragment(info.fragment)
			}
			return ErrResourceUnmatched
		}
	}
	token, queued, err := t.flows.queuePacket(info, appID, pkt)
	if err != nil {
		return err
	}
	if queued {
		t.wakeAuth()
		return nil
	}
	frame, err := encodeDataFrame(token, pkt)
	if err != nil {
		return err
	}
	return t.write(frame)
}

// 拒包详情不可用作限速键；有限类别只带累计数量，不输出包地址或服务端文案。
func (t *tunnelConn) recordRejection(err error) {
	t.rejectMu.Lock()
	count, reason := &t.rejected.LinkUnavailable, packetlog.LinkUnavailable
	var protocolErr *ProtocolError
	switch {
	case errors.Is(err, ErrResourceUnmatched):
		count, reason = &t.rejected.ResourceUnmatched, packetlog.ResourceUnmatched
	case errors.Is(err, ErrFlowRejected):
		count, reason = &t.rejected.FlowRejected, packetlog.FlowRejected
	case errors.Is(err, ErrPendingFull):
		count, reason = &t.rejected.PendingFull, packetlog.PendingFull
	case errors.Is(err, ErrFlowTableFull):
		count, reason = &t.rejected.FlowTableFull, packetlog.FlowTableFull
	case errors.Is(err, ErrFragmentMissing):
		count, reason = &t.rejected.FragmentMissing, packetlog.FragmentMissing
	case errors.Is(err, ErrFragmentOrder):
		count, reason = &t.rejected.FragmentOrder, packetlog.FragmentOrder
	case errors.Is(err, ErrFragmentFull):
		count, reason = &t.rejected.FragmentFull, packetlog.FragmentFull
	case errors.Is(err, ErrPacketTooLarge):
		count, reason = &t.rejected.MTUExceeded, packetlog.MTUExceeded
	case errors.As(err, &protocolErr):
		count, reason = &t.rejected.InvalidPacket, packetlog.InvalidPacket
	}
	now := time.Now()
	*count += 1
	n := *count
	report := t.rejectLogAt.IsZero() || now.Sub(t.rejectLogAt) >= 10*time.Second
	if report {
		t.rejectLogAt = now
	}
	t.rejectMu.Unlock()
	if report && t.logf != nil {
		t.logf("%s", packetlog.Format(packetlog.TunnelRejection, reason, n))
	}
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
		if err := t.conn.SetReadDeadline(time.Now().Add(heartbeatInterval * heartbeatMissLimit)); err != nil {
			t.close(dial.Wrap("设置隧道读期限", err))
			return
		}
		fr, err := readFrame(t.r)
		if err != nil {
			t.close(dial.Wrap("隧道读取", err))
			return
		}
		// 收到任何服务端帧都算对端还活着。本地写成功不算：对端静默消失
		// （NAT、防火墙、断电）时写入照样成功，只有“收到过东西”才说明
		// 链路真的还在，否则有上行流量时判死形同虚设。
		t.heartbeatGap.Store(0)
		switch fr.cmd {
		case cmdDataResp:
			stream, err = appendStream(stream, fr.payload)
			if err != nil {
				t.close(err)
				return
			}
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

// appendStream 把一帧的载荷接进下行累计缓冲，超过上限即报协议错误。
func appendStream(stream, payload []byte) ([]byte, error) {
	if len(payload) > maxStreamBytes-len(stream) {
		return nil, &ProtocolError{What: "下行累计缓冲超过上限"}
	}
	return append(stream, payload...), nil
}

// handleAuthResp 记录令牌并把该流缓存的包补发出去。
//
// 注意状态字节为 0 也可能是失败：会话失效时服务端正是这么回的。
func (t *tunnelConn) handleAuthResp(status byte, payload []byte) {
	var resp struct {
		Code *int `json:"code"`
		Data struct {
			ConnectToken  string  `json:"connectToken"`
			ConntrackHash *uint64 `json:"conntrackHash"`
		} `json:"data"`
	}
	if err := json.Unmarshal(payload, &resp); err != nil {
		t.close(&ProtocolError{What: "鉴权响应格式非法"})
		return
	}
	// 会话失效属于共享登录；即使没有单流哈希也必须立即结束连接。
	if resp.Code != nil && *resp.Code == codeSessionGone {
		t.close(&ErrSessionGone{Code: *resp.Code})
		return
	}
	if resp.Code == nil || resp.Data.ConntrackHash == nil || *resp.Data.ConntrackHash == 0 {
		t.close(&ProtocolError{What: "鉴权响应缺少 code 或 conntrackHash"})
		return
	}
	if status == authRetryStatus && t.flows.retryAuth(*resp.Data.ConntrackHash) {
		t.logAuthRetry()
		return
	}
	if status != 0 || *resp.Code != 0 {
		t.flows.completeAuth(*resp.Data.ConntrackHash, "", ErrFlowRejected)
		return
	}
	if len(resp.Data.ConnectToken) == 0 || len(resp.Data.ConnectToken) > 255 {
		t.close(&ProtocolError{What: "鉴权响应令牌长度非法"})
		return
	}
	_, pending := t.flows.completeAuth(*resp.Data.ConntrackHash, resp.Data.ConnectToken, nil)
	if len(pending) == 0 {
		return
	}
	for len(pending) > 0 {
		n := min(authBatchSize, len(pending))
		frame, err := encodeDataFrame(resp.Data.ConnectToken, pending[:n]...)
		if err != nil {
			t.close(err)
			return
		}
		if err := t.write(frame); err != nil {
			t.close(err)
			return
		}
		pending = pending[n:]
	}
}

func (t *tunnelConn) logAuthRetry() {
	if t.logf == nil {
		return
	}
	now := time.Now().UnixNano()
	last := t.authRetryLogAt.Load()
	if now-last < int64(authRetryLogInterval) || !t.authRetryLogAt.CompareAndSwap(last, now) {
		return
	}
	t.logf("逐流鉴权暂未就绪（状态 0x%02X），已安排 %s 后的一次重试", authRetryStatus, flowAuthRetryDelay)
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
		// 两个值一起更新：承载层的映射读端点上的地址（上下行改写都用它），
		// VIP 供状态与后续判断读。它们描述的是同一个事实，不能只改一半。
		t.ep.SetLocalAddr(v4)
		t.logf("服务端已更新隧道地址")
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
	}
	return true
}

func (t *tunnelConn) sendAuthRequest(f authFlow) error {
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
func (t *tunnelConn) buildAuthRequest(f authFlow) ([]byte, error) {
	ipProto := int(protoTCP)
	switch f.key.proto {
	case protoUDP:
		ipProto = protoUDP
	case protoICMP:
		ipProto = protoICMP
	}
	env, hash := processEnvironment()

	req := authRequestJSON{
		Sid:           t.sid,
		AppID:         f.appID,
		URL:           fmt.Sprintf("%s:%s:%d", protoName(f.key.proto), f.key.dstString(), f.key.dport),
		DeviceID:      t.deviceID,
		ConnectionID:  t.connectionID,
		ConntrackHash: f.authID,
		Lang:          "en-US",
		IP: authIPJSON{
			Atype: 0x0800, Protocol: ipProto,
			DestAddr: f.key.dstString(), DestPort: int(f.key.dport),
			SrcAddr: f.key.srcString(), SrcPort: int(f.key.sport),
		},
		ProcHash: hash,
		Env:      env,
	}

	unsigned, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	return signAuthJSON(unsigned, t.signKey), nil
}

func signAuthJSON(unsigned, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(unsigned)
	sig := hex.EncodeToString(mac.Sum(nil))
	return append([]byte(string(unsigned[:len(unsigned)-1])), []byte(fmt.Sprintf(",%q:%q}", "xRequestSig", upperHex(sig)))...)
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
		if t.unregister != nil {
			t.unregister()
		}
		if t.raw != nil {
			_ = t.raw.Close()
		}
		_ = t.conn.Close()
		if t.flows != nil {
			t.flows.clear()
		}
		if err != nil {
			t.logf("隧道断开: %v", err)
		}
	})
}

// Close 供重连逻辑使用：关掉连接并注销上行回调。
func (t *tunnelConn) Close() error {
	t.close(nil)
	t.workers.Wait()
	return nil
}
