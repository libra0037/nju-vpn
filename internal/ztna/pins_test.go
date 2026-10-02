package ztna

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestSPKIPinSurvivesCertificateRenewal(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256(spki)
	input := [][32]byte{expected}
	verifier := newNodeSPKIPins(input)
	input[0] = [32]byte{} // 配置输入发生变化不能改动已构造的信任快照。
	for _, serial := range []int64{1, 2} {
		start := time.Unix(1700000000, 0).AddDate(int(serial)-1, 0, 0)
		tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "sdp"}, NotBefore: start, NotAfter: start.AddDate(1, 0, 0)}
		der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, DidResume: true}
		if err := verifier.verify(state); err != nil {
			t.Fatal("同一公钥的续签证书被拒绝", err)
		}
		derPin := newNodeSPKIPins([][32]byte{sha256.Sum256(der)})
		if !errors.Is(derPin.verify(state), ErrNodeUntrusted) {
			t.Fatal("整张证书摘要不能充当 SPKI pin")
		}
	}
	wrong := newNodeSPKIPins([][32]byte{{1}})
	leaf := &x509.Certificate{RawSubjectPublicKeyInfo: spki}
	if !errors.Is(wrong.verify(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}), ErrNodeUntrusted) {
		t.Fatal("陌生公钥被接受")
	}
}

func TestSPKIFixedSampleAndRevokedSnapshot(t *testing.T) {
	const sample = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q=="
	// 摘要由独立 Python hashlib 对上述固定字节计算，不由被测校验器推导。
	const fingerprint = "XNJS+wzokyQ2+vjM0QQJgbie5K1rn+niorfnGqyyfNM="
	spki, err := base64.StdEncoding.DecodeString(sample)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParsePKIXPublicKey(spki); err != nil {
		t.Fatal("固定样例须为有效 DER SPKI", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	var pin [32]byte
	copy(pin[:], decoded)
	leaf := &x509.Certificate{RawSubjectPublicKeyInfo: spki}
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, DidResume: true}
	configured := newNodeSPKIPins([][32]byte{pin, {1}})
	if err := configured.verify(state); err != nil {
		t.Fatal("固定 SPKI 摘要对象错误", err)
	}
	revoked := newNodeSPKIPins([][32]byte{{1}})
	if !errors.Is(revoked.verify(state), ErrNodeUntrusted) {
		t.Fatal("新快照仍接受已撤销公钥")
	}
}

func TestPinsCannotBeBypassed(t *testing.T) {
	for _, p := range []*nodeSPKIPins{nil, newNodeSPKIPins(nil), newNodeSPKIPins([][32]byte{{1}})} {
		if !errors.Is(p.verify(tls.ConnectionState{}), ErrNodeUntrusted) {
			t.Fatal("无证书或无白名单仍通过")
		}
	}
	calls := 0
	_, err := dialTunnel(t.Context(), tunnelOptions{Dial: func(_ context.Context, _, _ string) (net.Conn, error) { calls++; return nil, errors.New("called") }})
	if !errors.Is(err, ErrNodeUntrusted) || calls != 0 {
		t.Fatal("nil 校验器仍拨号")
	}
}
