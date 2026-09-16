package main

import (
	"flag"
	"reflect"
	"testing"
)

// 回归（原 F1）：参数解析改由标准库决定，这里钉住几种写法。
//
// 以前是自己实现的 splitFlags / joinPositional：两处必须永远一致，
// 而且"布尔 flag 紧跟位置参数"这类组合会解析错。
func TestParseInterleaved(t *testing.T) {
	cases := []struct {
		name       string
		args       []string
		wantConfig string
		wantDebug  bool
		wantPos    []string
	}{
		{
			name:       "flag 在前",
			args:       []string{"-config", "a.yaml", "123456"},
			wantConfig: "a.yaml",
			wantPos:    []string{"123456"},
		},
		{
			name:       "flag 在后",
			args:       []string{"123456", "-config", "a.yaml"},
			wantConfig: "a.yaml",
			wantPos:    []string{"123456"},
		},
		{
			name:       "等号写法",
			args:       []string{"123456", "-config=a.yaml"},
			wantConfig: "a.yaml",
			wantPos:    []string{"123456"},
		},
		{
			name:      "布尔 flag 后面跟位置参数",
			args:      []string{"-debug", "123456"},
			wantDebug: true,
			wantPos:   []string{"123456"},
		},
		{
			name:       "多个位置参数",
			args:       []string{"12", "-config", "a.yaml", "34"},
			wantConfig: "a.yaml",
			wantPos:    []string{"12", "34"},
		},
		{
			name:    "双横线终止符后全算位置参数",
			args:    []string{"--", "-config"},
			wantPos: []string{"-config"},
		},
		{
			name:    "没有参数",
			args:    nil,
			wantPos: nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := flag.NewFlagSet("t", flag.ContinueOnError)
			configPath := fs.String("config", "", "")
			debug := fs.Bool("debug", false, "")
			pos, err := parseInterleaved(fs, c.args)
			if err != nil {
				t.Fatalf("解析失败: %v", err)
			}
			if *configPath != c.wantConfig {
				t.Errorf("-config = %q，期望 %q", *configPath, c.wantConfig)
			}
			if *debug != c.wantDebug {
				t.Errorf("-debug = %v，期望 %v", *debug, c.wantDebug)
			}
			if !reflect.DeepEqual(pos, c.wantPos) {
				t.Errorf("位置参数 = %q，期望 %q", pos, c.wantPos)
			}
		})
	}
}

// 未知 flag 必须报错，而不是被当成位置参数悄悄吞掉。
func TestParseInterleavedRejectsUnknownFlag(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(discard{})
	fs.String("config", "", "")
	if _, err := parseInterleaved(fs, []string{"-nope", "x"}); err == nil {
		t.Fatal("未知 flag 应当报错")
	}
}

// discard 吞掉 flag 包打到 stderr 的用法提示，保持测试输出干净。
type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
