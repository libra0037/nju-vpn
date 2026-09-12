package ipc

import (
	"bufio"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

// 回归：没有长度上限时，一个只发不换行的连接能让服务进程内存无界增长。
func TestReadRequestRejectsOversizedLine(t *testing.T) {
	line := strings.Repeat("a", MaxLineBytes+1024)
	r := bufio.NewReaderSize(strings.NewReader(line), 4096)

	if _, err := ReadRequest(r); !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("超长行应返回 ErrLineTooLong，实际 %v", err)
	}
}

// 刚好到上限的行必须能正常解析。
func TestReadRequestAcceptsLineAtLimit(t *testing.T) {
	cmd := "status " + strings.Repeat("a", MaxLineBytes-20)
	r := bufio.NewReaderSize(strings.NewReader(cmd+"\n"), 4096)

	req, err := ReadRequest(r)
	if err != nil {
		t.Fatalf("上限内的行不该报错: %v", err)
	}
	if req.Command != "status" {
		t.Errorf("命令解析错误: %q", req.Command)
	}
}

func TestReadRequestParsesArgs(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("auth 123456\n"))
	req, err := ReadRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	if req.Command != CmdAuth || len(req.Args) != 1 || req.Args[0] != "123456" {
		t.Errorf("解析结果 = %+v", req)
	}
}

// 响应必须是单行：服务端的错误信息里可能带换行。
func TestFormatResponseStaysOnOneLine(t *testing.T) {
	out := FormatResponse(Response{Code: CodeServerError, Message: "第一行\n第二行\r第三行"})
	if strings.Count(out, "\n") != 1 {
		t.Errorf("响应包含多余换行: %q", out)
	}
	if !strings.HasSuffix(out, "\n") {
		t.Errorf("响应必须以换行结束: %q", out)
	}
}

func TestParseResponseRejectsGarbage(t *testing.T) {
	if _, err := ParseResponse("x\n"); err == nil {
		t.Error("非法状态码应报错")
	}
	if _, err := ParseResponse("\n"); err == nil {
		t.Error("空响应应报错")
	}
}

// 回归（原 F13）：响应行的编解码。
//
// 以前 ParseResponse 用 Sscanf 读前三个字符、再硬切第 5 列，
// "2000 x" 会被解析成 code=200、msg="1 x"。
func TestResponseRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		resp Response
	}{
		{"普通消息", Response{Code: 200, Message: "隧道已建立"}},
		{"空消息", Response{Code: 409, Message: ""}},
		{"消息本身以数字开头", Response{Code: 200, Message: "1234 个包"}},
		{"多行消息被压成一行", Response{Code: 500, Message: "第一行\n第二行"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			line := FormatResponse(c.resp)
			got, err := ParseResponse(line)
			if err != nil {
				t.Fatalf("解析 %q 失败: %v", line, err)
			}
			if got.Code != c.resp.Code {
				t.Errorf("状态码 = %d，期望 %d", got.Code, c.resp.Code)
			}
			wantMsg := sanitize(c.resp.Message)
			if got.Message != wantMsg {
				t.Errorf("消息 = %q，期望 %q", got.Message, wantMsg)
			}
		})
	}
}

// 状态码必须够三位，否则整行不可信。
func TestParseResponseRejectsBadCode(t *testing.T) {
	for _, line := range []string{"20 ok", "abc ok", "2000", "200ok", "", "x"} {
		if _, err := ParseResponse(line); err == nil {
			t.Errorf("%q 应当解析失败", line)
		}
	}
}

// 超长消息在编码时就要截断：客户端会拒绝超长行，而它给出的提示
// （"报文行超过长度上限"）与真实错误毫无关系。
func TestFormatResponseTruncatesLongMessage(t *testing.T) {
	long := strings.Repeat("很长的错误信息", 8000)
	line := FormatResponse(Response{Code: 500, Message: long})
	if len(line) > MaxLineBytes {
		t.Fatalf("编码后 %d 字节，超过上限 %d", len(line), MaxLineBytes)
	}
	resp, err := ParseResponse(line)
	if err != nil {
		t.Fatalf("截断后的行应当可解析: %v", err)
	}
	if !strings.HasSuffix(resp.Message, "…（已截断）") {
		t.Errorf("截断后应带标记，末尾是 %q", tail(resp.Message, 12))
	}
	if !utf8.ValidString(resp.Message) {
		t.Error("截断不该切断多字节字符")
	}
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// TestSecretRoundTrip 验证口令这类字段能安全地放进文本行协议。
//
// 协议按空白切分参数，口令里可能有空格；编码同时让口令原文不出现在
// 任何报文转储里。
func TestSecretRoundTrip(t *testing.T) {
	cases := []string{
		"",
		"simple",
		"with space",
		"tab\tand\nnewline",
		"中文口令",
	}
	for _, want := range cases {
		encoded := EncodeSecret(want)
		if strings.ContainsAny(encoded, " \t\n") {
			t.Fatalf("编码后不该含空白字符: %q", encoded)
		}
		got, err := DecodeSecret(encoded)
		if err != nil {
			t.Fatalf("解码 %q 失败: %v", encoded, err)
		}
		if got != want {
			t.Fatalf("往返不一致: %q -> %q", want, got)
		}
	}
}

// TestDecodeSecretRejectsGarbage 验证乱码给出错误而不是静默的空口令。
func TestDecodeSecretRejectsGarbage(t *testing.T) {
	if _, err := DecodeSecret("not base64!!"); err == nil {
		t.Fatal("非法编码必须报错")
	}
}
