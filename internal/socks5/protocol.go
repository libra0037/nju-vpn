package socks5

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/libra0037/nju-vpn/internal/ztna"
)

// RFC 1928/1929 的字节布局。只支持 CONNECT、IPv4/域名及配置允许的一种认证。
const (
	version            byte = 5
	noAuth             byte = 0
	passwordAuth       byte = 2
	noMethod           byte = 255
	connectCommand     byte = 1
	ipv4Address        byte = 1
	domainAddress      byte = 3
	ipv6Address        byte = 4
	generalFailure     byte = 1
	ruleDenied         byte = 2
	networkUnreachable byte = 3
	hostUnreachable    byte = 4
	connectionRefused  byte = 5
	commandUnsupported byte = 7
	addressUnsupported byte = 8
)

func (s *Server) handle(ctx context.Context, conn net.Conn, connect DialFunc) error {
	if err := conn.SetDeadline(time.Now().Add(s.opts.HandshakeTimeout)); err != nil {
		return err
	}
	r := bufio.NewReader(conn)
	if err := s.negotiate(r, conn); err != nil {
		return err
	}
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	if header[0] != version || header[2] != 0 {
		_ = failureReply(conn, generalFailure)
		return errors.New("SOCKS 请求头非法")
	}
	if header[1] != connectCommand {
		_ = failureReply(conn, commandUnsupported)
		return errors.New("SOCKS 命令不支持")
	}
	var host string
	switch header[3] {
	case ipv4Address:
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return err
		}
		host = netip.AddrFrom4(ip).String()
	case domainAddress:
		var size [1]byte
		if _, err := io.ReadFull(r, size[:]); err != nil {
			return err
		}
		if size[0] == 0 {
			_ = failureReply(conn, addressUnsupported)
			return errors.New("SOCKS 空域名")
		}
		name := make([]byte, int(size[0]))
		if _, err := io.ReadFull(r, name); err != nil {
			return err
		}
		host = string(name)
	default:
		_ = failureReply(conn, addressUnsupported)
		return ztna.ErrTCPAddressUnsupported
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return err
	}
	target, err := ztna.NewTCPTarget(host, binary.BigEndian.Uint16(port[:]))
	if err != nil {
		_ = failureReply(conn, addressUnsupported)
		return err
	}
	select {
	case s.dialSlots <- struct{}{}:
	default:
		s.rejected.Add(1)
		_ = failureReply(conn, generalFailure)
		return errors.New("SOCKS 建连名额已满")
	}
	dialCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	// 本地连接的期限同样覆盖等待校园 CONNECT 回复和返回成功响应。
	if err := conn.SetDeadline(time.Now().Add(connectTimeout)); err != nil {
		cancel()
		<-s.dialSlots
		return err
	}
	upstream, err := connect(dialCtx, target)
	cancel()
	<-s.dialSlots
	if err != nil {
		_ = failureReply(conn, replyCode(err))
		return err
	}
	defer upstream.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close(); _ = upstream.Close() })
	defer stop()
	host, boundPort := upstream.BoundAddress()
	if err := successReply(conn, host, boundPort); err != nil {
		return err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return err
	}
	return relay(conn.(*net.TCPConn), r, upstream)
}

func (s *Server) negotiate(r io.Reader, w io.Writer) error {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return err
	}
	if head[0] != version || head[1] == 0 {
		return errors.New("SOCKS 方法请求非法")
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(r, methods); err != nil {
		return err
	}
	chosen := noMethod
	wanted := noAuth
	if s.auth {
		wanted = passwordAuth
	}
	for _, method := range methods {
		if method == wanted {
			chosen = wanted
			break
		}
	}
	if _, err := w.Write([]byte{version, chosen}); err != nil {
		return err
	}
	if chosen == noMethod {
		return errors.New("SOCKS 没有可接受的认证方法")
	}
	if !s.auth {
		return nil
	}
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return err
	}
	if head[0] != 1 || head[1] == 0 {
		_, _ = w.Write([]byte{1, 1})
		return errors.New("SOCKS 认证请求非法")
	}
	username := make([]byte, int(head[1]))
	if _, err := io.ReadFull(r, username); err != nil {
		return err
	}
	var length [1]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return err
	}
	password := make([]byte, int(length[0]))
	if _, err := io.ReadFull(r, password); err != nil {
		return err
	}
	ok := len(password) > 0 && s.authenticate(username, password)
	status := byte(1)
	if ok {
		status = 0
	}
	if _, err := w.Write([]byte{1, status}); err != nil {
		return err
	}
	if !ok {
		return errors.New("SOCKS 认证被拒绝")
	}
	return nil
}

func failureReply(w io.Writer, code byte) error {
	_, err := w.Write([]byte{version, code, 0, ipv4Address, 0, 0, 0, 0, 0, 0})
	return err
}
func successReply(w io.Writer, host string, port uint16) error {
	reply := []byte{version, 0, 0}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Is4() {
			reply = append(reply, ipv4Address)
		} else {
			reply = append(reply, ipv6Address)
		}
		reply = append(reply, ip.AsSlice()...)
	} else {
		if len(host) == 0 || len(host) > 255 {
			return errors.New("校园绑定地址非法")
		}
		reply = append(reply, domainAddress, byte(len(host)))
		reply = append(reply, host...)
	}
	reply = binary.BigEndian.AppendUint16(reply, port)
	_, err := w.Write(reply)
	return err
}

func replyCode(err error) byte {
	var target *ztna.TCPConnectError
	var netErr net.Error
	switch {
	case errors.As(err, &target):
		return target.Reply
	case errors.Is(err, ztna.ErrTCPResourceUnmatched), errors.Is(err, ztna.ErrTCPAuthRejected):
		return ruleDenied
	case errors.Is(err, ztna.ErrTCPAddressUnsupported):
		return addressUnsupported
	case errors.Is(err, syscall.ECONNREFUSED):
		return connectionRefused
	case errors.Is(err, syscall.ENETUNREACH):
		return networkUnreachable
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, context.DeadlineExceeded):
		return hostUnreachable
	case errors.As(err, &netErr) && netErr.Timeout():
		return hostUnreachable
	default:
		return generalFailure
	}
}

// 两个方向各有固定 32 KiB 缓冲。EOF 只关闭对侧写端，等待反向数据完成。
// 错误须打断另一方向；任务由当前处理器等待，不在已建立流上重试。
func relay(client *net.TCPConn, reader io.Reader, upstream Stream) error {
	results := make(chan error, 2)
	go func() {
		_, err := io.CopyBuffer(struct{ io.Writer }{upstream}, struct{ io.Reader }{reader}, make([]byte, copyBufferBytes))
		if err == nil {
			err = upstream.CloseWrite()
		}
		results <- err
	}()
	go func() {
		_, err := io.CopyBuffer(struct{ io.Writer }{client}, struct{ io.Reader }{upstream}, make([]byte, copyBufferBytes))
		if err == nil {
			err = client.CloseWrite()
		}
		results <- err
	}()
	first := <-results
	if first != nil {
		_ = client.Close()
		_ = upstream.Close()
	}
	second := <-results
	return errors.Join(first, second)
}
