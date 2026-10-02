package ztna

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
)

// 口令用服务端下发的 RSA 公钥加密：明文是"口令_反重放随机数"，
// 公钥装不下时分段，密文拼起来转小写十六进制。
func parseRSAPublicKey(modulusHex, exponentStr string) (*rsa.PublicKey, error) {
	// 限制大整数解析与模幂成本；控制面整体字节上限不能替代运算预算。
	if len(modulusHex) > 2048 || len(exponentStr) > 10 {
		return nil, &ProtocolError{What: "服务端 RSA 公钥超过运算预算"}
	}
	n, ok := new(big.Int).SetString(modulusHex, 16)
	if !ok || n.Sign() <= 0 {
		return nil, &ProtocolError{What: "服务端公钥模数非法"}
	}
	e, err := strconv.Atoi(exponentStr)
	if err != nil || e < 3 || e%2 == 0 || uint64(e) > 1<<31-1 {
		return nil, &ProtocolError{What: "服务端公钥指数非法"}
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}

func encryptPassword(pub *rsa.PublicKey, plain string) (string, error) {
	if len(plain) > 8192 {
		return "", &ProtocolError{What: "口令加密输入超过 8192 字节"}
	}
	max := pub.Size() - 11
	if max <= 0 {
		return "", &ProtocolError{What: "服务端公钥过小"}
	}
	msg := []byte(plain)
	out := make([]byte, 0, pub.Size()*((len(msg)+max-1)/max+1))
	for len(msg) > 0 {
		n := min(len(msg), max)
		//lint:ignore SA1019 服务端协议只认 PKCS#1 v1.5，换 OAEP 会直接登录失败
		chunk, err := rsa.EncryptPKCS1v15(rand.Reader, pub, msg[:n])
		if err != nil {
			return "", err
		}
		out = append(out, chunk...)
		msg = msg[n:]
	}
	return hex.EncodeToString(out), nil
}

// NewDeviceID 生成一个设备标识，供服务进程首次启动时持久化。
//
// 它必须跨启动稳定：服务端用它认出"还是那台设备"，授信终端就绑在它身上。
//
// 熵源读不出来时报错，不退回固定值：一个写死的标识会让踩到同一分支的机器
// 共用同一个设备身份（授信终端跟着串号），而日志里看不出任何征兆。
func NewDeviceID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("生成设备标识: %w", err)
	}
	return hex.EncodeToString(b), nil
}
