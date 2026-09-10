package wireguard

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// Key 是 WireGuard 使用的 32 字节 Curve25519 密钥。
type Key [32]byte

// KeyLen 是密钥的字节数。
const KeyLen = 32

// GenerateKey 生成一个新的私钥。
func GenerateKey() (Key, error) {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		return Key{}, fmt.Errorf("生成密钥: %w", err)
	}
	clampScalar(k[:])
	return k, nil
}

// clampScalar 按 RFC 7748 处理私钥的位。
//
// 生成的私钥必须先夹紧再使用：不夹紧的话，同一份私钥在某些实现里
// 推导出的公钥会不一致。
func clampScalar(b []byte) {
	b[0] &= 248
	b[31] &= 127
	b[31] |= 64
}

// PublicKey 由私钥推导公钥。
func (k Key) PublicKey() (Key, error) {
	out, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		return Key{}, fmt.Errorf("推导公钥: %w", err)
	}
	var pub Key
	copy(pub[:], out)
	return pub, nil
}

// String 返回 base64 形式，即配置文件与客户端配置里使用的写法。
func (k Key) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

// IsZero 报告密钥是否为空（全零）。
func (k Key) IsZero() bool { return k == Key{} }

// ParseKey 解析 base64 形式的密钥。
func ParseKey(s string) (Key, error) {
	var k Key
	if s == "" {
		return k, fmt.Errorf("密钥为空")
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return k, fmt.Errorf("密钥不是合法的 base64: %w", err)
	}
	if len(raw) != KeyLen {
		return k, fmt.Errorf("密钥长度 %d 字节，期望 %d", len(raw), KeyLen)
	}
	copy(k[:], raw)
	return k, nil
}
