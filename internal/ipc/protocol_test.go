package ipc

import (
	"bufio"
	"strings"
	"testing"
)

func TestParseRequestAndFormatResponse(t *testing.T) {
	req, err := ParseRequest("  start   trust=1 abcd  ")
	if err != nil {
		t.Fatal(err)
	}
	if req.Command != "start" || len(req.Args) != 2 || req.Args[0] != "trust=1" {
		t.Errorf("解析结果 = %+v", req)
	}
	if _, err := ParseRequest("   "); err == nil {
		t.Error("空请求应报错")
	}

	line := FormatResponse(Response{Code: CodeOK, Message: "好\n了"})
	if strings.Count(line, "\n") != 1 || !strings.HasSuffix(line, "\n") {
		t.Errorf("响应必须正好占一行，得到 %q", line)
	}
	resp, err := ParseResponse(line)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Code != CodeOK || resp.Message != "好 了" {
		t.Errorf("往返结果 = %+v", resp)
	}
}

func TestParseResponseRejectsMalformed(t *testing.T) {
	cases := []string{"", "200", "20 ok", "abc x"}
	for _, c := range cases {
		if _, err := ParseResponse(c); err == nil {
			t.Errorf("%q 应被拒绝", c)
		}
	}
}

func TestSecretRoundTrip(t *testing.T) {
	for _, secret := range []string{"pw", "带 空格 的口令", ""} {
		encoded := EncodeSecret(secret)
		if strings.ContainsAny(encoded, " 	") {
			t.Errorf("编码结果不该含空白: %q", encoded)
		}
		got, err := DecodeSecret(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if got != secret {
			t.Errorf("往返结果 = %q，期望 %q", got, secret)
		}
	}
	if _, err := DecodeSecret("不是 base64"); err == nil {
		t.Error("非法编码应报错")
	}
}

func TestBoolArg(t *testing.T) {
	cases := []struct {
		arg   string
		want  bool
		isErr bool
	}{
		{"", false, false},
		{"all=0", false, false},
		{"all=1", true, false},
		{"trust=1", false, true},
		{"all=yes", false, true},
		{"all", false, true},
	}
	for _, c := range cases {
		got, err := BoolArg(c.arg, "all")
		if (err != nil) != c.isErr {
			t.Errorf("BoolArg(%q) 错误 = %v，期望出错 = %v", c.arg, err, c.isErr)
		}
		if err == nil && got != c.want {
			t.Errorf("BoolArg(%q) = %v，期望 %v", c.arg, got, c.want)
		}
	}
	if Arg([]string{"a", "b"}, 1) != "b" || Arg([]string{"a"}, 3) != "" || Arg(nil, -1) != "" {
		t.Error("Arg 的取值不对")
	}
}

func TestLineTooLong(t *testing.T) {
	long := strings.Repeat("x", MaxLineBytes+10) + "\n"
	if _, err := ReadRequest(bufio.NewReader(strings.NewReader(long))); err == nil {
		t.Error("超长行应被拒绝")
	}
}

func TestRequestResponseRoundTrip(t *testing.T) {
	var buf strings.Builder
	if err := WriteRequest(&buf, Request{Command: CmdUntrust, Args: []string{"all=1"}}); err != nil {
		t.Fatal(err)
	}
	req, err := ReadRequest(bufio.NewReader(strings.NewReader(buf.String())))
	if err != nil {
		t.Fatal(err)
	}
	if req.Command != CmdUntrust || len(req.Args) != 1 || req.Args[0] != "all=1" {
		t.Errorf("往返结果 = %+v", req)
	}
}
