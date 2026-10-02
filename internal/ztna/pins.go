package ztna

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
)

var ErrNodeUntrusted = errors.New("节点公钥不在配置的 SPKI 白名单中")

// nodeSPKIPins 发布后不再修改；没有地址、磁盘记录或首次使用状态。
type nodeSPKIPins struct {
	allowed [][sha256.Size]byte
}

func newNodeSPKIPins(allowed [][sha256.Size]byte) *nodeSPKIPins {
	return &nodeSPKIPins{allowed: slices.Clone(allowed)}
}

// verify 包括恢复连接；TLS 已经解析证书，摘要对象只取叶子的 DER SPKI。
func (p *nodeSPKIPins) verify(state tls.ConnectionState) error {
	if p == nil || len(p.allowed) == 0 || len(state.PeerCertificates) == 0 || state.PeerCertificates[0] == nil {
		return ErrNodeUntrusted
	}
	sum := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
	if slices.Contains(p.allowed, sum) {
		return nil
	}
	return fmt.Errorf("%w（SPKI SHA-256=%s）", ErrNodeUntrusted, base64.StdEncoding.EncodeToString(sum[:]))
}
