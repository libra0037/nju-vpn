// Package domain 统一校园资源和 IPC 的 ASCII 域名接入语法。
package domain

import "strings"

const (
	maxNameBytes    = 253
	maxPatternStars = 8
)

// Normalize 只接受 ASCII/punycode，移除一个根点并转小写；pattern 允许最多 8 个 *。
func Normalize(value string, pattern bool) (string, bool) {
	value = strings.TrimSuffix(value, ".")
	if len(value) == 0 || len(value) > maxNameBytes {
		return "", false
	}
	labelStart, stars := 0, 0
	for i := 0; i <= len(value); i++ {
		if i == len(value) || value[i] == '.' {
			if i == labelStart || i-labelStart > 63 || value[labelStart] == '-' || value[i-1] == '-' {
				return "", false
			}
			labelStart = i + 1
			continue
		}
		c := value[i]
		if c == '*' && pattern {
			stars++
			if stars > maxPatternStars {
				return "", false
			}
			continue
		}
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' {
			continue
		}
		return "", false
	}
	return strings.ToLower(value), true
}
