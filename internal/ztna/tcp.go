package ztna

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/libra0037/nju-vpn/internal/dial"
	"github.com/libra0037/nju-vpn/internal/domain"
)

var (
	ErrTCPAddressUnsupported = errors.New("TCP 目标地址类型不支持")
	ErrTCPResourceUnmatched  = errors.New("TCP 目标未匹配校园资源")
	ErrTCPAuthRejected       = errors.New("校园 TCP 鉴权被拒绝")
)

// TCPConnectError 只携带 SOCKS 定义的有限目标建连类别，不携带地址或服务端文案。
type TCPConnectError struct{ Reply byte }

func (e *TCPConnectError) Error() string {
	return fmt.Sprintf("校园 TCP 目标建连失败（%d）", e.Reply)
}

const (
	tcpMethod         byte = 0x81
	tcpAuthMode       byte = 0x03
	tcpDialTimeout         = 15 * time.Second
	tcpAttemptTimeout      = 5 * time.Second
	// 单节点时可遍历一条资源最多 64 个 IP；多节点仍受同一个总尝试预算约束。
	maxTCPDialAttempts = 64
)

// TCPConn 是校园 L4 的普通字节流。会话拥有连接集合，调用方拥有读写任务。
// CloseWrite 发送 TLS close_notify；收到 EOF 后仍可继续反向传输。
// 绑定地址来自校园 CONNECT 回复，LocalAddr 仍表示节点连接的本地套接字。
type TCPConn struct {
	conn      *tls.Conn
	reader    *bufio.Reader
	session   *Session
	boundHost string
	boundPort uint16
	closeOnce sync.Once
	closeErr  error
}

func (c *TCPConn) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	if err == io.EOF {
		return n, err
	}
	return n, dial.Wrap("校园 TCP 读取", err)
}
func (c *TCPConn) Write(p []byte) (int, error) {
	n, err := c.conn.Write(p)
	return n, dial.Wrap("校园 TCP 写入", err)
}
func (c *TCPConn) CloseWrite() error {
	return dial.Wrap("校园 TCP 写侧关闭", c.conn.CloseWrite())
}
func (c *TCPConn) BoundAddress() (string, uint16) { return c.boundHost, c.boundPort }
func (c *TCPConn) LocalAddr() net.Addr            { return c.conn.LocalAddr() }
func (c *TCPConn) RemoteAddr() net.Addr           { return c.conn.RemoteAddr() }
func (c *TCPConn) SetDeadline(t time.Time) error {
	return dial.Wrap("校园 TCP 设置期限", c.conn.SetDeadline(t))
}
func (c *TCPConn) SetReadDeadline(t time.Time) error {
	return dial.Wrap("校园 TCP 设置读期限", c.conn.SetReadDeadline(t))
}
func (c *TCPConn) SetWriteDeadline(t time.Time) error {
	return dial.Wrap("校园 TCP 设置写期限", c.conn.SetWriteDeadline(t))
}
func (c *TCPConn) Close() error {
	c.closeOnce.Do(func() {
		// 先关闭原始套接字，不能等一个被背压阻塞的 TLS 写锁。
		c.closeErr = dial.Wrap("校园 TCP 关闭", c.conn.NetConn().Close())
		if c.session != nil {
			c.session.mu.Lock()
			delete(c.session.tcpConnections, c)
			c.session.mu.Unlock()
		}
	})
	return c.closeErr
}

// DialTCP 只拼接校园 L4；从不直接解析或拨号业务目标，也不使用 L3。
// 握手总预算、尝试数和会话取消覆盖所有候选；已建立流不会重连或重放。
func (s *Session) DialTCP(ctx context.Context, target TCPTarget) (*TCPConn, error) {
	if target.port == 0 {
		return nil, &ProtocolError{What: "TCP 目标零值无效"}
	}
	s.mu.Lock()
	if s.closed || s.ctx.Err() != nil || s.table == nil {
		s.mu.Unlock()
		return nil, ErrResourcesUnavailable
	}
	table := s.table
	s.dials.Add(1)
	s.mu.Unlock()
	defer s.dials.Done()
	route, ok := table.matchTCP(target)
	if !ok {
		return nil, ErrTCPResourceUnmatched
	}
	nodes := table.candidateNodes(route.grant.nodeGroupID)
	if len(nodes) == 0 {
		return nil, &ProtocolError{What: "没有可用的校园节点"}
	}
	ctx, cancel := context.WithTimeout(ctx, tcpDialTimeout)
	stop := context.AfterFunc(s.ctx, cancel)
	defer func() { stop(); cancel() }()
	var lastErr error
	count := 0
	// 每个 IP 依次尝试节点。没有下发 IP 时只使用实际域名或字面 IPv4。
	for i := 0; i < max(1, len(route.dialIPs)); i++ {
		for _, node := range nodes {
			if count >= maxTCPDialAttempts {
				return nil, lastErr
			}
			count++
			attemptCtx, attemptCancel := context.WithTimeout(ctx, tcpAttemptTimeout)
			conn, err := s.dialTCPNode(attemptCtx, node, route, i)
			attemptCancel()
			if err == nil {
				s.mu.Lock()
				if s.closed || s.ctx.Err() != nil || ctx.Err() != nil {
					s.mu.Unlock()
					_ = conn.Close()
					return nil, context.Canceled
				}
				conn.session = s
				s.tcpConnections[conn] = struct{}{}
				s.mu.Unlock()
				return conn, nil
			}
			lastErr = err
			var gone *ErrSessionGone
			if errors.As(err, &gone) {
				s.invalidate(gone)
				return nil, gone
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			var rejected *TCPConnectError
			var protocol *ProtocolError
			if errors.Is(err, ErrTCPAuthRejected) || errors.As(err, &protocol) || errors.As(err, &rejected) && rejected.Reply != 3 && rejected.Reply != 4 && rejected.Reply != 5 {
				return nil, err
			}
		}
	}
	return nil, lastErr
}

type tcpAuthRequest struct {
	SID          string  `json:"sid"`
	AppID        string  `json:"appId"`
	URL          string  `json:"url"`
	DeviceID     string  `json:"deviceId"`
	ConnectionID string  `json:"connectionId"`
	ProcHash     string  `json:"procHash"`
	UserName     string  `json:"userName"`
	AppliedInfo  int     `json:"rcAppliedInfo"`
	Lang         string  `json:"lang"`
	DestAddr     string  `json:"destAddr"`
	DestIP       string  `json:"destIP,omitempty"`
	Env          envJSON `json:"env"`
}

func (s *Session) tcpRequest(route tcpRoute, ipIndex int) ([]byte, error) {
	if s.sid() == "" {
		return nil, &ProtocolError{What: "校园 TCP 握手缺少 SID"}
	}
	destination := route.target.host
	destIP := ""
	if len(route.dialIPs) > 0 {
		destIP = route.dialIPs[ipIndex].String()
		destination = destIP
	}
	addr := net.JoinHostPort(route.target.host, strconv.Itoa(int(route.target.port)))
	env, hash := processEnvironment()
	body, err := json.Marshal(tcpAuthRequest{
		SID: s.sid(), AppID: route.grant.appID, URL: "tcp://" + addr, DeviceID: s.client.opts.DeviceID,
		ConnectionID: fmt.Sprintf("%X-%d", md5.Sum([]byte(s.client.opts.DeviceID)), time.Now().UnixMicro()),
		ProcHash:     hash, UserName: s.username, Lang: "en-US", DestAddr: addr, DestIP: destIP, Env: env,
	})
	if err != nil {
		return nil, err
	}
	body = signAuthJSON(body, s.signKey)
	if len(body) > 65535 {
		return nil, &ProtocolError{What: "校园 TCP 鉴权帧超过上限"}
	}
	request := binary.BigEndian.AppendUint16([]byte{Version, 1, tcpMethod, envelopeVersion, tcpAuthMode}, uint16(len(body)))
	request = append(request, body...)
	request = append(request, Version, 1, 0)
	if ip, err := netip.ParseAddr(destination); err == nil {
		request = append(request, 1)
		v4 := ip.As4()
		request = append(request, v4[:]...)
	} else {
		request = append(request, 3, byte(len(destination)))
		request = append(request, destination...)
	}
	return binary.BigEndian.AppendUint16(request, route.target.port), nil
}

func (s *Session) dialTCPNode(ctx context.Context, node string, route tcpRoute, ipIndex int) (*TCPConn, error) {
	conn, err := dialNodeTLS(ctx, tunnelOptions{Node: node, Server: s.client.opts.Server, Dial: s.client.opts.Dial, Pins: s.client.pins})
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			_ = conn.NetConn().Close()
		}
	}()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, dial.Wrap("校园 TCP 设置握手期限", err)
	}
	stop := watchCancel(ctx, conn)
	defer stop()
	request, err := s.tcpRequest(route, ipIndex)
	if err != nil {
		return nil, err
	}
	if n, err := conn.Write(request); err != nil {
		return nil, dial.Wrap("校园 TCP 发送握手", err)
	} else if n != len(request) {
		return nil, dial.Wrap("校园 TCP 发送握手", io.ErrShortWrite)
	}
	reader := bufio.NewReader(conn)
	host, port, err := readTCPReply(reader)
	if err != nil {
		return nil, err
	}
	stop()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, dial.Wrap("校园 TCP 清除握手期限", err)
	}
	success = true
	return &TCPConn{conn: conn, reader: reader, boundHost: host, boundPort: port}, nil
}

func readTCPReply(reader io.Reader) (string, uint16, error) {
	var head [6]byte
	if _, err := io.ReadFull(reader, head[:]); err != nil {
		return "", 0, dial.Wrap("校园 TCP 读鉴权头", err)
	}
	if head[0] != Version || head[1] != tcpMethod || head[2] != envelopeVersion {
		return "", 0, &ProtocolError{What: "校园 TCP 鉴权头非法"}
	}
	body := make([]byte, binary.BigEndian.Uint16(head[4:]))
	if _, err := io.ReadFull(reader, body); err != nil {
		return "", 0, dial.Wrap("校园 TCP 读鉴权体", err)
	}
	code, _, ok := parseEnvelopeCode(body)
	if !ok {
		return "", 0, &ProtocolError{What: "校园 TCP 鉴权缺少整数 code"}
	}
	if code == codeSessionGone {
		return "", 0, &ErrSessionGone{Code: code}
	}
	if head[3] != 0 || code != 0 {
		return "", 0, ErrTCPAuthRejected
	}
	var reply [4]byte
	if _, err := io.ReadFull(reader, reply[:]); err != nil {
		return "", 0, dial.Wrap("校园 TCP 读目标回复", err)
	}
	if reply[0] != Version || reply[2] != 0 || reply[1] > 8 {
		return "", 0, &ProtocolError{What: "校园 TCP 目标回复非法"}
	}
	var host string
	switch reply[3] {
	case 1, 4:
		length := 4
		if reply[3] == 4 {
			length = 16
		}
		var address [16]byte
		if _, err := io.ReadFull(reader, address[:length]); err != nil {
			return "", 0, dial.Wrap("校园 TCP 读绑定地址", err)
		}
		ip, _ := netip.AddrFromSlice(address[:length])
		host = ip.String()
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return "", 0, dial.Wrap("校园 TCP 读绑定域名长度", err)
		}
		body := make([]byte, int(length[0]))
		if _, err := io.ReadFull(reader, body); err != nil {
			return "", 0, dial.Wrap("校园 TCP 读绑定域名", err)
		}
		var ok bool
		host, ok = domain.Normalize(string(body), false)
		if !ok {
			return "", 0, &ProtocolError{What: "校园 TCP 绑定域名非法"}
		}
	default:
		return "", 0, &ProtocolError{What: "校园 TCP 绑定地址类型非法"}
	}
	var port [2]byte
	if _, err := io.ReadFull(reader, port[:]); err != nil {
		return "", 0, dial.Wrap("校园 TCP 读绑定端口", err)
	}
	if reply[1] != 0 {
		return "", 0, &TCPConnectError{Reply: reply[1]}
	}
	return host, binary.BigEndian.Uint16(port[:]), nil
}

func processEnvironment() (envJSON, string) {
	path := "/usr/bin/njuvpn"
	hash := fmt.Sprintf("%X", sha256.Sum256([]byte(path)))
	var env envJSON
	env.Application.Runtime.Process = processJSON{Name: clientIdentity, DigitalSignature: "TrustAppClosed", Platform: "Linux", Fingerprint: hash, Description: "TrustAppClosed", Path: path, Version: "TrustAppClosed", SecurityEnv: "normal"}
	env.Application.Runtime.ProcessTrusted = "TRUSTED"
	return env, hash
}
