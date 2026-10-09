package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadKeyBoundsAndRegularFiles(t *testing.T) {
	directory := t.TempDir()
	if _, err := readKey(directory); err == nil {
		t.Fatal("目录被接受为密钥文件")
	}
	for _, tc := range []struct {
		name string
		body string
		fail bool
	}{
		{"valid", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n", false},
		{"empty", "", true},
		{"malformed", strings.Repeat("x", 64), true},
		{"oversized", strings.Repeat("0", 65), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(directory, tc.name)
			if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			key, err := readKey(path)
			if (err != nil) != tc.fail {
				t.Fatal("密钥输入边界错误", err)
			}
			if !tc.fail {
				for _, value := range key {
					if value != 1 {
						t.Fatal("固定密钥解码错误")
					}
				}
			}
		})
	}
}
