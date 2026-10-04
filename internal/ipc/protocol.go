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
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// dialTimeout 是客户端连接服务进程的超时。
//
// 放在这里而不是各自的构建标签文件里：Unix 与 Windows 两侧的行为要一致，
// 而两份字面量靠注释提醒同步，改一边就会分叉。
const dialTimeout = 5 * time.Second

// 请求命令。每个命令的参数都是固定位置、固定个数，布尔值写成 名字=0/1：
// 这样"少写一个参数"与"写错一个值"不会互相冒充。
const (
	// CmdPing 探活。服务进程在运行就回 pong 与自己的身份。
	CmdPing = "ping"
	// CmdState 只回报状态名（idle / logging_in / ...）。
	//
	// 与 status 分开：那段是给人看的文本，格式随时会变，而 CLI 的幂等
	// 判断要靠状态做决定。按显示文本切第一段取值的话，显示格式一改，
	// 判断就静默失效了。
	CmdState = "state"
	// CmdStatus 返回状态与诊断；json 请求 JSON，check 在校园链路不在 up
	// 或正在重连时以 409 应答。两参数各最多一次，不检查业务目标可达。
	CmdStatus    = "status"
	CmdResources = "resources"
	// CmdStart 建立隧道：start <trust=0|1> [口令]。
	CmdStart = "start"
	// CmdAuth 提交二次验证码，继续上一次停下来的登录：auth <验证码>。
	CmdAuth = "auth"
	// CmdTrust 把本机绑成授信终端：trust [口令]。
	CmdTrust = "trust"
	// CmdUntrust 解除授信：untrust <all=0|1> [口令]。
	CmdUntrust = "untrust"
	// CmdStop 断开隧道。
	CmdStop = "stop"
	// CmdShutdown 让服务进程收尾（含登出）后退出，供 njuvpn restart 使用。
	CmdShutdown = "shutdown"
)

// 响应状态码。
const (
	CodeOK           = 200
	CodeBadRequest   = 400 // 参数不对，例如验证码错误
	CodeRejected     = 409 // 当前状态不允许该操作
	CodeAuthRequired = 428 // 需要提交验证码才能继续（不是错误）
	CodeServerError  = 500
)

// MaxLineBytes 是请求与响应的单行长度上限，包含分隔符与换行。
//
// 没有上限时，一个只发不换行的连接就能让服务进程的内存无界增长：
// bufio 的 ReadString 会一直扩容直到读到换行为止。
const MaxLineBytes = 64 * 1024

// ErrLineTooLong 表示收到的行超过对应请求或响应的上限。
var ErrLineTooLong = errors.New("报文行超过长度上限")
var ErrNotRunning = errors.New("服务进程未运行")
var ErrUntrustedPeer = errors.New("本地 IPC 对端身份不可信")

// Request 是一条解析后的请求。
type Request struct {
	Command string
	Args    []string
}

// EncodeSecret 把口令之类不能在命令行与日志里露面的字段编成一行文本。
//
// 协议按空白切分参数，口令里可能有空格；base64 仅用于编码，报文仍须保密。
func EncodeSecret(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// DecodeSecret 还原 EncodeSecret 编出来的字段。
func DecodeSecret(s string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("字段编码无法解析: %w", err)
	}
	return string(raw), nil
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
	code := strconv.Itoa(r.Code)
	// sanitize 只做等长替换；先拒绝超限消息，避免为了拒绝而分配整行。
	if len(code)+len(r.Message)+2 > MaxLineBytes {
		return fmt.Sprintf("%d 响应超过长度上限\n", CodeServerError)
	}
	return code + " " + sanitize(r.Message) + "\n"
}

// ParseResponse 解析一行响应。
func ParseResponse(line string) (Response, error) {
	line = strings.TrimRight(line, "\r\n")
	// 状态码与消息之间必须有一个空格：以前用 Sscanf 读前三个字符、
	// 再硬切第 5 列，"2000 x" 会被读成 code=200、msg="1 x"。
	codeText, msg, ok := strings.Cut(line, " ")
	if !ok {
		return Response{}, errors.New("响应缺少状态码或分隔符")
	}
	if len(codeText) < 3 || len(codeText) > 4 {
		return Response{}, errors.New("响应状态码位数不对")
	}
	code, err := strconv.Atoi(codeText)
	if err != nil {
		return Response{}, errors.New("响应状态码非法")
	}
	return Response{Code: code, Message: msg}, nil
}

// sanitize 保证消息只占一行，避免破坏行协议。
func sanitize(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// readLine 读一行，超过上限直接报错。
func readLine(r *bufio.Reader, limit int) (string, error) {
	var sb strings.Builder
	for {
		chunk, err := r.ReadSlice('\n')
		if sb.Len()+len(chunk) > limit {
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
	line, err := readLine(r, MaxLineBytes)
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
	line, err := readLine(r, MaxLineBytes)
	if err != nil {
		return Response{}, err
	}
	return ParseResponse(line)
}

// WriteRequest 向连接写一条请求。
func WriteRequest(w io.Writer, req Request) error {
	parts := append([]string{req.Command}, req.Args...)
	for _, part := range parts {
		if part == "" || strings.IndexFunc(part, func(r rune) bool { return r <= ' ' || r == 127 }) >= 0 {
			return errors.New("请求字段须为非空单行文本")
		}
	}
	line := strings.Join(parts, " ") + "\n"
	if len(line) > MaxLineBytes {
		return ErrLineTooLong
	}
	_, err := io.WriteString(w, line)
	return err
}

// Arg 取出第 i 个位置参数，缺失时返回空串。
func Arg(args []string, i int) string {
	if i < 0 || i >= len(args) {
		return ""
	}
	return args[i]
}

// BoolArg 解析形如 "名字=1" 的布尔参数，缺省（空串）是 false。
//
// 解析失败要报错而不是当成 false：把拼错的参数静默理解成默认值，正是
// "用户以为带了 --all，其实什么都没做"这类事故的来源。
func BoolArg(arg, name string) (bool, error) {
	if arg == "" {
		return false, nil
	}
	v, ok := strings.CutPrefix(arg, name+"=")
	if !ok {
		return false, fmt.Errorf("参数应为 %s=0/1", name)
	}
	switch v {
	case "1":
		return true, nil
	case "0":
		return false, nil
	default:
		return false, fmt.Errorf("参数 %s 只能是 0 或 1", name)
	}
}
