package domain

import (
	"strings"
	"testing"
)

func TestNormalizeBoundaries(t *testing.T) {
	maxName := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	for _, tc := range []struct {
		value    string
		pattern  bool
		want     string
		accepted bool
	}{
		{"DB.Example.EDU.", false, "db.example.edu", true},
		{"xn--bcher-kva.edu", false, "xn--bcher-kva.edu", true},
		{maxName, false, maxName, true},
		{maxName + "d", false, "", false},
		{strings.Repeat("a", 64) + ".edu", false, "", false},
		{strings.Repeat("*a", 8) + ".edu", true, strings.Repeat("*a", 8) + ".edu", true},
		{strings.Repeat("*a", 9) + ".edu", true, "", false},
		{"*.Example.EDU.", true, "*.example.edu", true},
		{"*.example.edu", false, "", false},
		{"a*-b.example.edu", true, "a*-b.example.edu", true},
		{"example.edu..", false, "", false},
		{"x..edu", false, "", false},
		{"x-.edu", false, "", false},
		{"-x.edu", false, "", false},
		{"x\x00.edu", false, "", false},
		{"中文.edu", false, "", false},
		{"https://example.edu", false, "", false},
	} {
		got, ok := Normalize(tc.value, tc.pattern)
		if got != tc.want || ok != tc.accepted {
			t.Fatalf("域名边界不符：accepted=%v want=%v", ok, tc.accepted)
		}
	}
}
