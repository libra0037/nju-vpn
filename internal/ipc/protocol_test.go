package ipc

import (
	"bufio"
	"errors"
	"strings"
	"testing"
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

func TestResponseRoundTrip(t *testing.T) {
	var sb strings.Builder
	want := Response{Code: CodeAuthRequired, Message: "需要验证码"}
	if err := WriteResponse(&sb, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadResponse(bufio.NewReader(strings.NewReader(sb.String())))
	if err != nil {
		t.Fatal(err)
	}
	if got.Code != want.Code || got.Message != want.Message {
		t.Errorf("往返结果 = %+v，期望 %+v", got, want)
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
