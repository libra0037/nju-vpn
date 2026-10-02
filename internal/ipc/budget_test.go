package ipc

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestResourcesResponseHasIndependentBudget(t *testing.T) {
	const app = `{"id":"app","nodeGroupId":"g","accessModel":"L3VPN","addressList":[{"host":"192.0.2.1","protocol":"tcp","port":"443","ip":null}]}`
	body := "[" + strings.TrimSuffix(strings.Repeat(app+",", 512), ",") + "]"
	// 独立固定布局：原始响应约 60 KiB；补出的 ip:null 令快照超过 64 KiB。
	if len(body) != 66561 {
		t.Fatal("固定样例长度改变", len(body))
	}
	var buf bytes.Buffer
	if err := WriteResourcesResponse(&buf, Response{Code: CodeOK, Message: body}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), []byte("200 "+body+"\n")) {
		t.Fatal("资源响应被替换或截断")
	}
	resp, err := ReadResourcesResponse(bufio.NewReader(bytes.NewReader(buf.Bytes())))
	if err != nil || resp.Code != CodeOK || resp.Message != body {
		t.Fatal("大资源响应未完整读取", err, resp.Code, len(resp.Message))
	}
	if _, err := ReadResponse(bufio.NewReader(bytes.NewReader(buf.Bytes()))); !errors.Is(err, ErrLineTooLong) {
		t.Fatal("普通响应的上限被放宽", err)
	}
	if _, err := ReadRequest(bufio.NewReader(bytes.NewReader(buf.Bytes()))); !errors.Is(err, ErrLineTooLong) {
		t.Fatal("请求上限被放宽", err)
	}
}

func TestResourcesResponseExactLimitAndOverflow(t *testing.T) {
	body := strings.Repeat("x", MaxResourcesResponseBytes-len("200 \n"))
	var buf bytes.Buffer
	if err := WriteResourcesResponse(&buf, Response{Code: CodeOK, Message: body}); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != MaxResourcesResponseBytes {
		t.Fatal("边界响应长度错误", buf.Len())
	}
	resp, err := ReadResourcesResponse(bufio.NewReader(bytes.NewReader(buf.Bytes())))
	if err != nil || resp.Code != CodeOK || resp.Message != body {
		t.Fatal("上限内的响应被拒绝", err)
	}
	buf.Reset()
	if err := WriteResourcesResponse(&buf, Response{Code: CodeOK, Message: body + "x"}); err != nil {
		t.Fatal(err)
	}
	resp, err = ReadResourcesResponse(bufio.NewReader(bytes.NewReader(buf.Bytes())))
	if err != nil || resp.Code != CodeServerError || strings.Contains(resp.Message, "xxxx") {
		t.Fatal("超限写出部分成功响应", err)
	}
	if _, err := ReadResourcesResponse(bufio.NewReader(strings.NewReader("200 " + body + "x\n"))); !errors.Is(err, ErrLineTooLong) {
		t.Fatal("未拒绝超限输入", err)
	}
}

func BenchmarkResourcesResponse(b *testing.B) {
	for _, size := range []int{1 << 20, MaxResourcesResponseBytes} {
		b.Run(map[int]string{1 << 20: "1MiB", MaxResourcesResponseBytes: "8MiB"}[size], func(b *testing.B) {
			resp := Response{Code: CodeOK, Message: strings.Repeat("x", size-len("200 \n"))}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := WriteResourcesResponse(io.Discard, resp); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestResponseRejectsCompleteEncodedOverflow(t *testing.T) {
	exact := Response{Code: 200, Message: strings.Repeat("a", MaxLineBytes-5)}
	if n := len(FormatResponse(exact)); n != MaxLineBytes {
		t.Fatal("上限以内的完整响应被改变", n)
	}
	over := FormatResponse(Response{Code: 200, Message: exact.Message + "b"})
	r, err := ParseResponse(over)
	if err != nil || r.Code != 500 || strings.Contains(r.Message, "aaaa") {
		t.Fatal("响应被截断", err)
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
