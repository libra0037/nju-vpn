package vpn

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	utls "github.com/refraction-networking/utls"
)

var ERR_NEXT_AUTH_SMS = errors.New("SMS Code required")
var ERR_NEXT_AUTH_TOTP = errors.New("Current user's TOTP bound")

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
	log.Printf("Twf Id: %s", twfId)

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
	log.Printf("Password to encrypt: %s", password)

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
	log.Printf("Encrypted Password: %s", encryptedPasswordHex)

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

		if !strings.Contains(string(buf[:n]), "验证码已发送到您的手机") && !strings.Contains(string(buf[:n]), "<USER_PHONE>") {
			return "", errors.New("unexpected sms resp: " + serverMessage(buf[:n]))
		}

		log.Printf("SMS Code is sent or still valid.")

		return twfId, ERR_NEXT_AUTH_SMS
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
		log.Printf("Update twfId: %s", twfId)
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

	if !strings.Contains(string(buf[:n]), "Auth sms suc") {
		return "", errors.New("SMS code verification failed: " + serverMessage(buf[:n]))
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
