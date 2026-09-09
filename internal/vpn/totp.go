package vpn

import (
	"fmt"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// GenerateTOTP 用 Base32 密钥生成当前时刻的 TOTP 验证码（6 位、30 秒、SHA1）。
func GenerateTOTP(secret string) (string, error) {
	secret = strings.TrimSpace(strings.ReplaceAll(secret, " ", ""))
	if secret == "" {
		return "", fmt.Errorf("TOTP 密钥为空")
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		return "", fmt.Errorf("生成 TOTP 验证码: %w", err)
	}
	return code, nil
}

// ValidateTOTPSecret 检查密钥格式是否合法。
func ValidateTOTPSecret(secret string) error {
	_, err := otp.NewKeyFromURL("otpauth://totp/x?secret=" + strings.TrimSpace(secret))
	return err
}
