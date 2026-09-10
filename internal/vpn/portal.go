package vpn

import (
	"context"
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
	"strconv"
	"strings"
)

// portalErr 是 portal 接口返回的错误，附带服务端说明。
type portalErr struct {
	Step   string
	Reason string
}

func (e *portalErr) Error() string { return e.Step + ": " + e.Reason }

// readBody 读完整响应体，带长度上限。
//
// 旧实现用一次 resp.Body.Read(buf) 读 40960 字节，短读很常见
// （响应分多个 TCP 段到达），关键标记落在读到的片段之外就会走错分支。
func readBody(resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("读取响应体: %w", err)
	}
	return body, nil
}

// do 发一个 portal 请求并把响应体读全。
func (c *Client) do(ctx context.Context, method, path string, form url.Values, twfID string) ([]byte, error) {
	addr := "https://" + c.server + path
	log.Printf("%s %s", method, addr)

	var reqBody io.Reader
	if form != nil {
		reqBody = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, addr, reqBody)
	if err != nil {
		return nil, fmt.Errorf("构造请求 %s: %w", path, err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if twfID != "" {
		req.Header.Set("Cookie", "TWFID="+twfID)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 %s: %w", path, err)
	}
	defer resp.Body.Close()

	body, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &portalErr{Step: path, Reason: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, serverMessage(body))}
	}
	return body, nil
}

// webLogin 完成第一阶段的 Web 登录，返回 TwfID。
//
// 若服务端要求二次验证，返回的 error 是 *AuthRequiredError，
// 里面带着会话标识和验证方式，调用方据此索取验证码后继续。
func (c *Client) webLogin(ctx context.Context, username, password string) (string, error) {
	const step = "web-login"

	body, err := c.do(ctx, http.MethodGet, "/por/login_auth.csp?apiversion=1", nil, "")
	if err != nil {
		return "", err
	}

	twfID, err := requireTag(step, body, "TwfID")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(twfID) == "" {
		return "", &ProtocolError{Step: step, Reason: "服务端返回了空的 TwfID"}
	}
	log.Printf("Twf Id: %s", redact(twfID))

	rsaKeyHex, err := requireTag(step, body, "RSA_ENCRYPT_KEY")
	if err != nil {
		return "", err
	}
	rsaExp := "65537"
	if v, ok := tagValue(body, "RSA_ENCRYPT_EXP"); ok && strings.TrimSpace(v) != "" {
		rsaExp = strings.TrimSpace(v)
	} else {
		log.Printf("服务端未提供 RSA_ENCRYPT_EXP，使用默认值 65537")
	}

	csrfCode, hasCSRF := tagValue(body, "CSRF_RAND_CODE")
	if hasCSRF {
		password += "_" + csrfCode
	} else {
		log.Printf("服务端未提供 CSRF_RAND_CODE，按旧版本服务端处理")
	}

	pubKey, err := parsePublicKey(step, rsaKeyHex, rsaExp)
	if err != nil {
		return "", err
	}
	// 密码和它的密文都不能进日志：明文是凭据本身，密文配合公开的
	// RSA 公钥和 CSRF 码可以离线爆破。
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, []byte(password))
	if err != nil {
		return "", fmt.Errorf("%s: 加密口令: %w", step, err)
	}

	form := url.Values{
		"svpn_rand_code":    {""},
		"mitm":              {""},
		"svpn_req_randcode": {csrfCode},
		"svpn_name":         {username},
		"svpn_password":     {hex.EncodeToString(encrypted)},
	}
	body, err = c.do(ctx, http.MethodPost, "/por/login_psw.csp?anti_replay=1&encrypt=1&type=cs", form, twfID)
	if err != nil {
		return "", err
	}

	switch {
	case tagContains(body, "NextService", "auth/sms"), tagContains(body, "NextAuth", "2"):
		log.Print("服务端要求短信验证码")
		state, err := c.requestSMS(ctx, twfID)
		if err != nil {
			return "", err
		}
		return twfID, &AuthRequiredError{Kind: ErrAuthSMS, TwfID: twfID, State: state}

	case tagContains(body, "NextService", "auth/token"), tagContains(body, "NextServiceSubType", "totp"):
		log.Print("服务端要求 TOTP 验证码")
		return twfID, &AuthRequiredError{Kind: ErrAuthTOTP, TwfID: twfID}
	}

	if hasTag(body, "NextAuth") && !tagContains(body, "NextAuth", "-1") {
		return "", &portalErr{Step: step, Reason: "不支持的二次验证方式: " + serverMessage(body)}
	}
	if !tagContains(body, "Result", "1") {
		return "", &portalErr{Step: step, Reason: "登录失败: " + serverMessage(body)}
	}

	if v, ok := tagValue(body, "TwfID"); ok && v != "" {
		twfID = v
		log.Printf("登录后的 TwfId: %s", redact(twfID))
	}
	log.Print("Web 登录完成")
	return twfID, nil
}

// requestSMS 请求服务端发送一条短信验证码。
//
// 返回的 state 非 nil 表示请求被受理（ErrSMSSent / ErrSMSTooMany 等），
// 由上层决定怎么提示用户。
func (c *Client) requestSMS(ctx context.Context, twfID string) (error, error) {
	body, err := c.do(ctx, http.MethodPost, "/por/login_sms.csp?apiversion=1", nil, twfID)
	if err != nil {
		return nil, err
	}
	return classifySMSRequest(body)
}

// authSMS 提交短信验证码，返回更新后的 TwfID。
func (c *Client) authSMS(ctx context.Context, twfID, code string) (string, error) {
	form := url.Values{"svpn_inputsms": {code}}
	body, err := c.do(ctx, http.MethodPost, "/por/login_sms1.csp?apiversion=1", form, twfID)
	if err != nil {
		return "", err
	}
	if state, err := classifySMSAuth(body); err != nil {
		return "", err
	} else if state != nil {
		return "", state
	}
	newTwfID, ok := tagValue(body, "TwfID")
	if !ok || newTwfID == "" {
		return twfID, nil
	}
	log.Print("短信验证码校验通过")
	return newTwfID, nil
}

// authTOTP 提交 TOTP 验证码，返回更新后的 TwfID。
func (c *Client) authTOTP(ctx context.Context, twfID, code string) (string, error) {
	form := url.Values{"svpn_inputtoken": {code}}
	body, err := c.do(ctx, http.MethodPost, "/por/login_token.csp", form, twfID)
	if err != nil {
		return "", err
	}
	if state, err := classifySMSAuth(body); err != nil {
		return "", err
	} else if state != nil {
		return "", state
	}
	newTwfID, ok := tagValue(body, "TwfID")
	if !ok || newTwfID == "" {
		return twfID, nil
	}
	log.Print("TOTP 校验通过")
	return newTwfID, nil
}

// portalToken 取得后续二进制流协议使用的 token。
func (c *Client) portalToken(ctx context.Context, twfID string) (string, error) {
	const step = "portal-token"

	conn, err := c.portalTLS(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if err := conn.SetDeadline(deadlineFrom(ctx, c.timeouts.Handshake)); err != nil {
		return "", err
	}

	// 服务端把隧道 token 藏在 TLS ServerHello 的 SessionId 里：
	// 用有效 TWFID 连一次并请求 conf/rclist，ServerHello 的 SessionId
	// 前 31 个十六进制字符就是 token 的主体。
	req := "GET /por/conf.csp HTTP/1.1\r\nHost: " + c.server + "\r\nCookie: TWFID=" + twfID + "\r\n\r\n" +
		"GET /por/rclist.csp HTTP/1.1\r\nHost: " + c.server + "\r\nCookie: TWFID=" + twfID + "\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return "", fmt.Errorf("%s: 发送 portal 请求: %w", step, err)
	}

	sessionID, err := serverSessionID(conn)
	if err != nil {
		return "", err
	}
	// 只记长度：token 就是它的十六进制前缀，写进日志等于把会话交出去。
	log.Printf("Server Session ID: %d 字节", len(sessionID))

	// 读到第一个字节说明握手确实完成了、请求也确实被受理。
	if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
		return "", fmt.Errorf("%s: 读取 portal 响应: %w", step, err)
	}

	return sessionIDToken(step, sessionID)
}

// Logout 通知服务端结束会话。
//
// 这一步很重要：服务端对同一账号的隧道会话数有限制，本地直接关闭连接
// 不会释放服务端侧的名额，长期会累积到无法再建隧道。
func (c *Client) Logout(ctx context.Context, twfID string) error {
	if twfID == "" {
		return errors.New("TWFID 为空，无法登出")
	}
	body, err := c.do(ctx, http.MethodGet, "/por/logout.csp", nil, twfID)
	if err != nil {
		return err
	}
	return classifyLogout(body)
}

// parsePublicKey 解析服务端返回的 RSA 公钥。
//
// 旧实现忽略了两个解析错误，于是服务端改版时会从 rsa.EncryptPKCS1v15
// 抛出"指数太小"之类的误导性错误。
func parsePublicKey(step, keyHex, exp string) (*rsa.PublicKey, error) {
	e, err := strconv.Atoi(strings.TrimSpace(exp))
	if err != nil || e < 3 {
		return nil, &ProtocolError{Step: step, Reason: fmt.Sprintf("RSA_ENCRYPT_EXP 非法: %q", exp)}
	}
	modulus := new(big.Int)
	if _, ok := modulus.SetString(strings.TrimSpace(keyHex), 16); !ok || modulus.Sign() <= 0 {
		return nil, &ProtocolError{Step: step, Reason: "RSA_ENCRYPT_KEY 不是合法的十六进制大整数"}
	}
	return &rsa.PublicKey{N: modulus, E: e}, nil
}
