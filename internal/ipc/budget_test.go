package ipc

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestResponseReadWriteExactLimitAndOverflow(t *testing.T) {
	body := strings.Repeat("x", MaxLineBytes-len("200 \n"))
	var buf bytes.Buffer
	if err := WriteResponse(&buf, Response{Code: CodeOK, Message: body}); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != MaxLineBytes {
		t.Fatal("边界响应长度错误", buf.Len())
	}
	resp, err := ReadResponse(bufio.NewReader(bytes.NewReader(buf.Bytes())))
	if err != nil || resp.Code != CodeOK || resp.Message != body {
		t.Fatal("上限内的响应被拒绝", err)
	}
	buf.Reset()
	if err := WriteResponse(&buf, Response{Code: CodeOK, Message: body + "x"}); err != nil {
		t.Fatal(err)
	}
	resp, err = ReadResponse(bufio.NewReader(bytes.NewReader(buf.Bytes())))
	if err != nil || resp.Code != CodeServerError || strings.Contains(resp.Message, "xxxx") {
		t.Fatal("超限写出部分成功响应", err)
	}
	if _, err := ReadResponse(bufio.NewReader(strings.NewReader("200 " + body + "x\n"))); !errors.Is(err, ErrLineTooLong) {
		t.Fatal("未拒绝超限输入", err)
	}
	if _, err := ReadRequest(bufio.NewReader(strings.NewReader(strings.Repeat("x", MaxLineBytes) + "\n"))); !errors.Is(err, ErrLineTooLong) {
		t.Fatal("请求上限被放宽", err)
	}
}

func BenchmarkResponse(b *testing.B) {
	resp := Response{Code: CodeOK, Message: strings.Repeat("x", MaxLineBytes-len("200 \n"))}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := WriteResponse(io.Discard, resp); err != nil {
			b.Fatal(err)
		}
	}
}

func TestRequestRejectsOverflowAndLineInjectionBeforeWriting(t *testing.T) {
	for _, req := range []Request{
		{Command: "auth", Args: []string{"123\nshutdown"}},
		{Command: "start", Args: []string{strings.Repeat("a", MaxLineBytes)}},
	} {
		var buf bytes.Buffer
		err := WriteRequest(&buf, req)
		if err == nil || buf.Len() != 0 {
			t.Fatal("非法请求已部分写出")
		}
	}
	var buf bytes.Buffer
	err := WriteRequest(&buf, Request{Command: strings.Repeat("a", MaxLineBytes)})
	if !errors.Is(err, ErrLineTooLong) {
		t.Fatal(err)
	}
}
