package vpn

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

var ERR_NEXT_AUTH_SMS = errors.New("SMS Code required")
var ERR_NEXT_AUTH_TOTP = errors.New("Current user's TOTP bound")

// 短信相关的结果状态。服务端用同一组响应表达"发了新码""旧码还有效""码错了"，
// 调用方需要区分它们才能给出正确的提示，否则用户会一直等一条不会来的短信。
var (
	// ErrSMSSent 表示服务端刚刚发了一条新短信。
	ErrSMSSent = errors.New("验证码已发送到手机")
	// ErrSMSStillValid 表示上一条验证码仍在有效期内，服务端没有重发。
	ErrSMSStillValid = errors.New("上一条验证码仍然有效，未重发")
	// ErrSMSWrongCode 表示验证码错误。
	ErrSMSWrongCode = errors.New("验证码错误")
	// ErrSMSExpired 表示验证码已过期，需要重新获取。
	ErrSMSExpired = errors.New("验证码已过期")
	// ErrSMSTooMany 表示请求过于频繁，被服务端限流。
	ErrSMSTooMany = errors.New("短信发送过于频繁")
)

// redact 只保留字符串的两端，用于在日志里标识一个凭据而不泄露它。
func redact(s string) string {
	if len(s) <= 4 {
		return "***"
	}
	return s[:2] + "***" + s[len(s)-2:]
}

// RequestSMS 请求服务端发送一条短信验证码。
// 冷却期内服务端不会重发，此时返回 ErrSMSStillValid。
func (client *Client) RequestSMS(twfId string) error {
	c := client.httpClient()
	buf := make([]byte, 40960)

	addr := "https://" + client.server + "/por/login_sms.csp?apiversion=1"
	req, err := http.NewRequest("POST", addr, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Cookie", "TWFID="+twfId)

	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	n, _ := resp.Body.Read(buf)
	state, err := classifySMSRequest(buf[:n])
	if err != nil {
		return err
	}
	if state != nil {
		return state
	}
	return nil
}

// classifySMSRequest 判断发送验证码请求的结果。
func classifySMSRequest(body []byte) (error, error) {
	s := string(body)

	// IS_IN_PERIOD=1 表示服务端认为上一条验证码仍在有效期内，本次没有发新短信。
	// 响应里同时带有"验证码已发送到您的手机"的模板文案和 <USER_PHONE>，
	// 所以必须先用这个标志判断，否则会把"冷却中"误报成"已发送"。
	if inPeriod(s) {
		return fmt.Errorf("%w（还需等待 %s）", ErrSMSStillValid, smsInterval(s)), nil
	}

	switch {
	case strings.Contains(s, "验证码已发送到您的手机"):
		return ErrSMSSent, nil
	case strings.Contains(s, "<USER_PHONE>"):
		return ErrSMSStillValid, nil
	case strings.Contains(s, "频繁") || strings.Contains(s, "too many") || strings.Contains(s, "TooMany"):
		return ErrSMSTooMany, nil
	case strings.Contains(s, "失败") || strings.Contains(s, "fail"):
		return nil, errors.New("发送验证码失败: " + serverMessage(body))
	}
	return nil, errors.New("unexpected sms resp: " + serverMessage(body))
}

// inPeriod 判断服务端是否处于短信冷却期。
func inPeriod(body string) bool {
	m := regexp.MustCompile(`<IS_IN_PERIOD>(\d+)</IS_IN_PERIOD>`).FindStringSubmatch(body)
	return m != nil && m[1] == "1"
}

// smsInterval 提取还需要等待的秒数。
func smsInterval(body string) string {
	for _, tag := range []string{"SmsSendInterval", "SMS_INTERVAL"} {
		m := regexp.MustCompile("<" + tag + ">(\\d+)</" + tag + ">").FindStringSubmatch(body)
		if m != nil {
			return m[1] + " 秒"
		}
	}
	return "一段时间"
}

// SMSCooldown 从错误里解析出还需要等待的时间。
// 解析不出来时返回 0。
func SMSCooldown(err error) time.Duration {
	if err == nil {
		return 0
	}
	re := regexp.MustCompile(`还需等待 (\d+) 秒`)
	m := re.FindStringSubmatch(err.Error())
	if m == nil {
		return 0
	}
	secs, err := strconv.Atoi(m[1])
	if err != nil || secs <= 0 {
		return 0
	}
	return time.Duration(secs) * time.Second
}

// UserMessage 去掉内部错误的前缀，只保留给用户看的部分。
// 例如 "SMS Code required: 上一条验证码仍然有效，未重发（还需等待 156 秒）"
// 会变成 "上一条验证码仍然有效，未重发（还需等待 156 秒）"。
func UserMessage(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	// errors.Join 用换行连接多个错误，fmt.Errorf 用 ": "，两种都要处理。
	if i := strings.LastIndex(msg, "\n"); i >= 0 {
		msg = msg[i+1:]
	}
	if i := strings.LastIndex(msg, ": "); i >= 0 {
		return msg[i+2:]
	}
	return msg
}

// classifySMSAuth 判断提交验证码的结果。
func classifySMSAuth(body []byte) (error, error) {
	s := string(body)
	switch {
	case strings.Contains(s, "Auth sms suc"):
		return nil, nil
	case strings.Contains(s, "过期") || strings.Contains(s, "expire"):
		return ErrSMSExpired, nil
	case strings.Contains(s, "错误") || strings.Contains(s, "invalid") || strings.Contains(s, "Invalid"):
		return ErrSMSWrongCode, nil
	case strings.Contains(s, "频繁") || strings.Contains(s, "too many"):
		return ErrSMSTooMany, nil
	}
	return nil, errors.New("SMS code verification failed: " + serverMessage(body))
}

// serverMessage 从服务端返回的 XML 里提取可读的错误信息。
// 直接把整个响应体塞进错误里，日志会变得没法看。
func serverMessage(body []byte) string {
	s := string(body)
	for _, tag := range []string{"Message", "ErrorMsg", "Note"} {
		re := regexp.MustCompile("<" + tag + ">(?:<!\\[CDATA\\[)?(.*?)(?:\\]\\]>)?</" + tag + ">")
		if m := re.FindStringSubmatch(s); m != nil && strings.TrimSpace(m[1]) != "" {
			return strings.TrimSpace(m[1])
		}
	}
	if m := regexp.MustCompile(`<ErrorCode>(.*)</ErrorCode>`).FindStringSubmatch(s); m != nil {
		return "错误码 " + m[1]
	}
	return "服务端返回了未预期的响应"
}

// WebLogin 完成第一阶段的 Web 登录，返回 TwfID。
// 若服务端要求二次验证，返回 ERR_NEXT_AUTH_SMS 或 ERR_NEXT_AUTH_TOTP。
func (client *Client) WebLogin(username string, password string) (string, error) {
	server := "https://" + client.server
	c := client.httpClient()

	addr := server + "/por/login_auth.csp?apiversion=1"
	log.Printf("Login Request: %s", addr)

	resp, err := c.Get(addr)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	buf := make([]byte, 40960)
	n, _ := resp.Body.Read(buf)

	twfId := string(regexp.MustCompile(`<TwfID>(.*)</TwfID>`).FindSubmatch(buf[:n])[1])
	log.Printf("Twf Id: %s", redact(twfId))

	rsaKey := string(regexp.MustCompile(`<RSA_ENCRYPT_KEY>(.*)</RSA_ENCRYPT_KEY>`).FindSubmatch(buf[:n])[1])
	log.Printf("RSA Key: %s", rsaKey)

	rsaExpMatch := regexp.MustCompile(`<RSA_ENCRYPT_EXP>(.*)</RSA_ENCRYPT_EXP>`).FindSubmatch(buf[:n])
	rsaExp := ""
	if rsaExpMatch != nil {
		rsaExp = string(rsaExpMatch[1])
	} else {
		log.Printf("Warning: No RSA_ENCRYPT_EXP, using default.")
		rsaExp = "65537"
	}
	log.Printf("RSA Exp: %s", rsaExp)

	csrfMatch := regexp.MustCompile(`<CSRF_RAND_CODE>(.*)</CSRF_RAND_CODE>`).FindSubmatch(buf[:n])
	csrfCode := ""
	if csrfMatch != nil {
		csrfCode = string(csrfMatch[1])
		log.Printf("CSRF Code: %s", csrfCode)
		password += "_" + csrfCode
	} else {
		log.Printf("WARNING: No CSRF Code Match. Maybe you're connecting to an older server? Continue anyway...")
	}
	// 密码和它的密文都不能进日志：明文是凭据本身，密文配合公开的
	// RSA 公钥和 CSRF 码可以离线爆破。

	pubKey := rsa.PublicKey{}
	pubKey.E, _ = strconv.Atoi(rsaExp)
	moduls := big.Int{}
	moduls.SetString(rsaKey, 16)
	pubKey.N = &moduls

	encryptedPassword, err := rsa.EncryptPKCS1v15(rand.Reader, &pubKey, []byte(password))
	if err != nil {
		return "", err
	}
	encryptedPasswordHex := hex.EncodeToString(encryptedPassword)
	log.Printf("已加密密码（%d 字节密文）", len(encryptedPasswordHex)/2)

	addr = server + "/por/login_psw.csp?anti_replay=1&encrypt=1&type=cs"
	log.Printf("Login Request: %s", addr)

	form := url.Values{
		"svpn_rand_code":    {""},
		"mitm":              {""},
		"svpn_req_randcode": {csrfCode},
		"svpn_name":         {username},
		"svpn_password":     {encryptedPasswordHex},
	}

	req, err := http.NewRequest("POST", addr, strings.NewReader(form.Encode()))
	req.Header.Set("Cookie", "TWFID="+twfId)

	resp, err = c.Do(req)
	if err != nil {
		return "", err
	}

	n, _ = resp.Body.Read(buf)
	defer resp.Body.Close()

	// log.Printf("First stage login response: %s", string(buf[:n]))

	// SMS Code Process
	if strings.Contains(string(buf[:n]), "<NextService>auth/sms</NextService>") || strings.Contains(string(buf[:n]), "<NextAuth>2</NextAuth>") {
		log.Print("SMS code required.")

		addr = server + "/por/login_sms.csp?apiversion=1"
		log.Printf("SMS Request: %s", addr)
		req, err = http.NewRequest("POST", addr, nil)
		req.Header.Set("Cookie", "TWFID="+twfId)

		resp, err = c.Do(req)
		if err != nil {
			return "", err
		}

		n, _ := resp.Body.Read(buf)
		defer resp.Body.Close()

		smsState, err := classifySMSRequest(buf[:n])
		if err != nil {
			return "", err
		}
		log.Printf("短信状态: %v", smsState)

		// 同时包装两个错误，上层既能用 errors.Is 判断需要二次验证，
		// 也能知道短信到底是新发了、复用旧码还是被限流。
		return twfId, fmt.Errorf("%w: %w", ERR_NEXT_AUTH_SMS, smsState)
	}

	// TOTP Authnication Process (Edited by JHong)
	if strings.Contains(string(buf[:n]), "<NextService>auth/token</NextService>") || strings.Contains(string(buf[:n]), "<NextServiceSubType>totp</NextServiceSubType>") {
		log.Print("TOTP Authnication required.")
		return twfId, ERR_NEXT_AUTH_TOTP
	}

	if strings.Contains(string(buf[:n]), "<NextAuth>-1</NextAuth>") || !strings.Contains(string(buf[:n]), "<NextAuth>") {
		log.Print("No NextAuth found.")
	} else {
		return "", errors.New("not implemented auth: " + serverMessage(buf[:n]))
	}

	if !strings.Contains(string(buf[:n]), "<Result>1</Result>") {
		return "", errors.New("login failed: " + serverMessage(buf[:n]))
	}

	twfIdMatch := regexp.MustCompile(`<TwfID>(.*)</TwfID>`).FindSubmatch(buf[:n])
	if twfIdMatch != nil {
		twfId = string(twfIdMatch[1])
		log.Printf("Update twfId: %s", redact(twfId))
	}

	log.Printf("Web Login process done.")

	return twfId, nil
}

// AuthSms 提交短信验证码，返回更新后的 TwfID。
func (client *Client) AuthSms(twfId string, smsCode string) (string, error) {
	server := client.server
	c := client.httpClient()

	buf := make([]byte, 40960)

	addr := "https://" + server + "/por/login_sms1.csp?apiversion=1"
	log.Printf("SMS Request: %s", addr)
	form := url.Values{
		"svpn_inputsms": {smsCode},
	}

	req, err := http.NewRequest("POST", addr, strings.NewReader(form.Encode()))
	req.Header.Set("Cookie", "TWFID="+twfId)

	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}

	n, _ := resp.Body.Read(buf)
	defer resp.Body.Close()

	if state, err := classifySMSAuth(buf[:n]); err != nil {
		return "", err
	} else if state != nil {
		return "", state
	}

	twfId = string(regexp.MustCompile(`<TwfID>(.*)</TwfID>`).FindSubmatch(buf[:n])[1])
	log.Print("SMS Code verification SUCCESS")

	return twfId, nil
}

// TOTPAuth 提交 TOTP 验证码，返回更新后的 TwfID。
func (client *Client) TOTPAuth(twfId string, totpCode string) (string, error) {
	server := client.server
	c := client.httpClient()

	buf := make([]byte, 40960)

	addr := "https://" + server + "/por/login_token.csp"
	log.Printf("TOTP token Request: %s", addr)
	form := url.Values{
		"svpn_inputtoken": {totpCode},
	}

	req, err := http.NewRequest("POST", addr, strings.NewReader(form.Encode()))
	req.Header.Set("Cookie", "TWFID="+twfId)

	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}

	n, _ := resp.Body.Read(buf)
	defer resp.Body.Close()

	if !strings.Contains(string(buf[:n]), "suc") {
		return "", errors.New("TOTP code verification failed: " + serverMessage(buf[:n]))
	}

	twfId = string(regexp.MustCompile(`<TwfID>(.*)</TwfID>`).FindSubmatch(buf[:n])[1])
	log.Print("TOTP verification SUCCESS")

	return twfId, nil
}

// PortalToken 取得后续二进制流协议使用的前 31 字节 token。
func (client *Client) PortalToken(twfId string) (string, error) {
	server := client.server
	dialConn, err := client.Dial()
	if err != nil {
		return "", err
	}
	defer dialConn.Close()
	conn := utls.UClient(dialConn, &utls.Config{InsecureSkipVerify: true}, utls.HelloGolang)
	defer conn.Close()

	// WTF???
	// When you establish a HTTPS connection to server and send a valid request with TWFID to it
	// The **TLS ServerHello SessionId** is the first part of token
	log.Printf("portal request: /por/conf.csp & /por/rclist.csp")
	io.WriteString(conn, "GET /por/conf.csp HTTP/1.1\r\nHost: "+server+"\r\nCookie: TWFID="+twfId+"\r\n\r\nGET /por/rclist.csp HTTP/1.1\r\nHost: "+server+"\r\nCookie: TWFID="+twfId+"\r\n\r\n")

	log.Printf("Server Session ID: %q", conn.HandshakeState.ServerHello.SessionId)

	buf := make([]byte, 40960)
	n, err := conn.Read(buf)
	if n == 0 || err != nil {
		return "", errors.New("portal request failed: " + err.Error())
	}

	return hex.EncodeToString(conn.HandshakeState.ServerHello.SessionId)[:31] + "\x00", nil
}
