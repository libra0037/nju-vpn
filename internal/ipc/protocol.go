// Package ipc 提供服务进程与命令行客户端之间的本地通信。
//
// 传输层是本地套接字（Linux 用 unix socket，Windows 用命名管道），
// 应用层是一行一条的文本协议：
//
//	请求  <命令> [参数...] 换行
//	响应  <状态码> <一行文本> 换行
//
// 状态码沿用 HTTP 的语义：200 成功，4xx 客户端错误，5xx 服务端错误。
// 这里没有用 HTTP，因为本地 IPC 不需要分帧、头字段和内容协商。
package ipc

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// 请求命令。
const (
	CmdStart  = "start"  // 建立隧道
	CmdStop   = "stop"   // 断开隧道
	CmdStatus = "status" // 查询状态
	CmdAuth   = "auth"   // 提交验证码
	CmdPing   = "ping"   // 探活
	// CmdShutdown 让服务进程收尾（含登出）后退出，供 njuvpn restart 使用。
	CmdShutdown = "shutdown"
	// CmdSetPeer 更新 WireGuard 接入方的公钥，不重建隧道。
	CmdSetPeer = "wg-peer"
	// CmdWGStats 查询 WireGuard 收发统计，用来判断客户端到底通没通。
	CmdWGStats = "wg-stats"
)

// 响应状态码。
const (
	CodeOK           = 200
	CodeBadRequest   = 400 // 参数不对，例如验证码错误
	CodeRejected     = 409 // 当前状态不允许该操作
	CodeAuthRequired = 428 // 需要提交验证码才能继续（不是错误）
	CodeServerError  = 500
)

// MaxLineBytes 是单行请求或响应的长度上限。
//
// 没有上限时，一个只发不换行的连接就能让服务进程的内存无界增长：
// bufio 的 ReadString 会一直扩容直到读到换行为止。
const MaxLineBytes = 64 * 1024

// ErrLineTooLong 表示收到的行超过 MaxLineBytes。
var ErrLineTooLong = errors.New("报文行超过长度上限")

// Request 是一条解析后的请求。
type Request struct {
	Command string
	Args    []string
}

// Response 是一条响应。Message 必须是单行文本。
type Response struct {
	Code    int
	Message string
}

// ParseRequest 解析一行请求。
func ParseRequest(line string) (Request, error) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) == 0 {
		return Request{}, fmt.Errorf("空请求")
	}
	return Request{Command: fields[0], Args: fields[1:]}, nil
}

// FormatResponse 把响应编码成一行。
func FormatResponse(r Response) string {
	msg := sanitize(r.Message)
	// 客户端会拒绝超长行，与其让对端收到一个与真实错误无关的提示
	//（"报文行超过长度上限"），不如在这里截断并标出来。
	const reserved = len("4294967295 ")
	if max := MaxLineBytes - reserved; len(msg) > max {
		msg = truncateUTF8(msg, max-len("…（已截断）")) + "…（已截断）"
	}
	return fmt.Sprintf("%d %s\n", r.Code, msg)
}

// ParseResponse 解析一行响应。
func ParseResponse(line string) (Response, error) {
	line = strings.TrimRight(line, "\r\n")
	// 状态码与消息之间必须有一个空格：以前用 Sscanf 读前三个字符、
	// 再硬切第 5 列，"2000 x" 会被读成 code=200、msg="1 x"。
	codeText, msg, ok := strings.Cut(line, " ")
	if !ok {
		return Response{}, fmt.Errorf("响应过短: %q", line)
	}
	if len(codeText) < 3 || len(codeText) > 4 {
		return Response{}, fmt.Errorf("响应状态码位数不对: %q", line)
	}
	code, err := strconv.Atoi(codeText)
	if err != nil {
		return Response{}, fmt.Errorf("响应状态码非法: %q", line)
	}
	return Response{Code: code, Message: msg}, nil
}

// truncateUTF8 按字节上限截断，但不切断多字节字符。
func truncateUTF8(s string, max int) string {
	if len(s) <= max {
		return s
	}
	for max > 0 && !utf8.RuneStart(s[max]) {
		max--
	}
	return s[:max]
}

// sanitize 保证消息只占一行，避免破坏行协议。
func sanitize(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// readLine 读一行，超过上限直接报错。
func readLine(r *bufio.Reader) (string, error) {
	var sb strings.Builder
	for {
		chunk, err := r.ReadSlice('\n')
		if sb.Len()+len(chunk) > MaxLineBytes {
			return "", ErrLineTooLong
		}
		sb.Write(chunk)
		switch {
		case err == nil:
			return sb.String(), nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			return "", err
		}
	}
}

// ReadRequest 从连接上读一条请求。
func ReadRequest(r *bufio.Reader) (Request, error) {
	line, err := readLine(r)
	if err != nil {
		return Request{}, err
	}
	return ParseRequest(line)
}

// WriteResponse 向连接写一条响应。
func WriteResponse(w io.Writer, resp Response) error {
	_, err := io.WriteString(w, FormatResponse(resp))
	return err
}

// ReadResponse 从连接上读一条响应。
func ReadResponse(r *bufio.Reader) (Response, error) {
	line, err := readLine(r)
	if err != nil {
		return Response{}, err
	}
	return ParseResponse(line)
}

// WriteRequest 向连接写一条请求。
func WriteRequest(w io.Writer, req Request) error {
	parts := append([]string{req.Command}, req.Args...)
	_, err := io.WriteString(w, strings.Join(parts, " ")+"\n")
	return err
}
