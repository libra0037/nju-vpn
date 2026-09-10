package wireguard

import (
	"encoding/hex"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// 密钥必须在 base64（配置里用）与 UAPI 的十六进制之间正确往返。
func TestKeyRoundTrip(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if key.IsZero() {
		t.Fatal("生成的私钥不应是全零")
	}

	text := key.String()
	parsed, err := ParseKey(text)
	if err != nil {
		t.Fatalf("解析自己生成的密钥失败: %v", err)
	}
	if parsed != key {
		t.Error("密钥往返后不一致")
	}

	// 私钥必须已按 RFC 7748 夹紧，否则不同实现推导出的公钥会不一致。
	if key[0]&7 != 0 || key[31]&128 != 0 || key[31]&64 == 0 {
		t.Errorf("私钥没有夹紧: 首字节 %08b 末字节 %08b", key[0], key[31])
	}
}

// 公钥推导要与 curve25519 直接计算的结果一致。
func TestPublicKeyMatchesCurve25519(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	want, err := curve25519.X25519(key[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(pub[:]) != hex.EncodeToString(want) {
		t.Error("公钥推导结果与 curve25519 不一致")
	}
	if pub == key {
		t.Error("公钥不应等于私钥")
	}
}

// 两台设备各自生成密钥时，互相推导出的公钥必须一致（Diffie-Hellman 基本性质）。
func TestKeyAgreementIsSymmetric(t *testing.T) {
	a, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	aPub, _ := a.PublicKey()
	bPub, _ := b.PublicKey()
	if aPub == bPub {
		t.Fatal("两个私钥推出了同一个公钥")
	}

	ab, err := curve25519.X25519(a[:], bPub[:])
	if err != nil {
		t.Fatal(err)
	}
	ba, err := curve25519.X25519(b[:], aPub[:])
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(ab) != hex.EncodeToString(ba) {
		t.Error("双方算出的共享密钥不一致")
	}
}

func TestParseKeyRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"空":         "",
		"不是 base64": "not base64!!!",
		"长度不足":      "AAAA",
		"长度过长":      strings.Repeat("A", 64),
	}
	for name, in := range cases {
		if _, err := ParseKey(in); err == nil {
			t.Errorf("%s 应被拒绝: %q", name, in)
		}
	}
}

// 回归：UAPI 里的密钥是十六进制而不是 base64，写错设备会直接报 invalid key。
func TestUAPIConfigUsesHexKeys(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	conf, err := uapiConfig(DeviceOptions{
		PrivateKey:    priv,
		ListenPort:    51820,
		PeerPublicKey: pub,
		PeerAddress:   net.ParseIP("10.66.66.2"),
	})
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(conf, "private_key="+hex.EncodeToString(priv[:])) {
		t.Errorf("私钥不是十六进制形式:\n%s", conf)
	}
	if !strings.Contains(conf, "public_key="+hex.EncodeToString(pub[:])) {
		t.Errorf("peer 公钥不是十六进制形式:\n%s", conf)
	}
	if strings.Contains(conf, priv.String()) {
		t.Error("配置里出现了 base64 形式的密钥")
	}
	if !strings.Contains(conf, "listen_port=51820") {
		t.Errorf("缺少监听端口:\n%s", conf)
	}
	if !strings.Contains(conf, "replace_peers=true") {
		t.Errorf("应清空旧的 peer，保证配置幂等:\n%s", conf)
	}
	if !strings.Contains(conf, "allowed_ip=10.66.66.2/32") {
		t.Errorf("缺少 allowed_ip:\n%s", conf)
	}
}

// 没有 peer 公钥时仍然要能启动，只是没有客户端能接入。
func TestUAPIConfigWithoutPeer(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	conf, err := uapiConfig(DeviceOptions{PrivateKey: priv, ListenPort: 51820})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(conf, "public_key=") {
		t.Errorf("没有 peer 时不该写 public_key:\n%s", conf)
	}
}

// peer 地址必须是 IPv4：协议层只承载 IPv4。
func TestUAPIConfigRejectsIPv6Peer(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := priv.PublicKey()
	_, err = uapiConfig(DeviceOptions{
		PrivateKey:    priv,
		ListenPort:    1,
		PeerPublicKey: pub,
		PeerAddress:   net.ParseIP("2001:db8::2"),
	})
	if err == nil {
		t.Error("IPv6 的 peer 地址应被拒绝")
	}
}
