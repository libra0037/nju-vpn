package ztnatest

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
)

// TCPRequest 是假节点独立解码的请求；返回副本供测试核对目标身份。
type TCPRequest struct {
	AppID    string `json:"appId"`
	URL      string `json:"url"`
	DestAddr string `json:"destAddr"`
	DestIP   string `json:"destIP"`
	Host     string
	Port     uint16
}

func (s *Server) TCPRequests() []TCPRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]TCPRequest(nil), s.tcpRequests...)
}

type tcpBufferedConn struct {
	*tls.Conn
	reader *bufio.Reader
}

func (c *tcpBufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (s *Server) handleTCP(conn *tls.Conn, reader *bufio.Reader) {
	var head [7]byte
	if _, err := io.ReadFull(reader, head[:]); err != nil || !bytes.Equal(head[:5], []byte{5, 1, 0x81, 0x53, 3}) {
		return
	}
	body := make([]byte, int(binary.BigEndian.Uint16(head[5:])))
	if _, err := io.ReadFull(reader, body); err != nil {
		return
	}
	var request TCPRequest
	if json.Unmarshal(body, &request) != nil {
		return
	}
	var target [4]byte
	if _, err := io.ReadFull(reader, target[:]); err != nil || !bytes.Equal(target[:3], []byte{5, 1, 0}) {
		return
	}
	switch target[3] {
	case 1:
		var ip [4]byte
		if _, err := io.ReadFull(reader, ip[:]); err != nil {
			return
		}
		request.Host = net.IP(ip[:]).String()
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(reader, size[:]); err != nil || size[0] == 0 {
			return
		}
		host := make([]byte, int(size[0]))
		if _, err := io.ReadFull(reader, host); err != nil {
			return
		}
		request.Host = string(host)
	default:
		return
	}
	var port [2]byte
	if _, err := io.ReadFull(reader, port[:]); err != nil {
		return
	}
	request.Port = binary.BigEndian.Uint16(port[:])
	s.mu.Lock()
	s.tcpRequests = append(s.tcpRequests, request)
	s.mu.Unlock()
	code := s.opts.L4AuthCode
	s.mu.Lock()
	loggedIn := s.loggedIn
	s.mu.Unlock()
	if !loggedIn {
		code = 75500002
	}
	body, _ = json.Marshal(map[string]any{"code": code})
	reply := binary.BigEndian.AppendUint16([]byte{5, 0x81, 0x53, 0}, uint16(len(body)))
	reply = append(reply, body...)
	if code != 0 {
		_, _ = conn.Write(reply)
		return
	}
	// 固定绑定地址 198.51.100.9:40000，与节点套接字完全不同。
	reply = append(reply, 5, s.opts.L4ConnectStatus, 0, 1, 198, 51, 100, 9, 0x9c, 0x40)
	if s.opts.L4ConnectStatus == 0 {
		reply = append(reply, s.opts.TCPGreeting...)
	}
	if _, err := conn.Write(reply); err != nil || s.opts.L4ConnectStatus != 0 {
		return
	}
	stream := &tcpBufferedConn{Conn: conn, reader: reader}
	if s.opts.TCPHandler != nil {
		s.opts.TCPHandler(stream)
		return
	}
	_, _ = io.Copy(stream, stream)
	_ = stream.CloseWrite()
}
