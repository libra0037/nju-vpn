package ztna

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"

	"github.com/libra0037/nju-vpn/internal/dial"
)

// 控制面：门户侧的 HTTPS 接口。所有路径与参数名都是与服务端的契约。
const (
	pathManifest      = "/public/manifest"
	pathAuthConfig    = "/passport/v1/public/authConfig"
	pathPasswordLogin = "/passport/v1/auth/psw"
	pathReportEnv     = "/controller/v1/public/reportEnv"
	pathAuthCheck     = "/passport/v1/auth/authCheck"
	pathPhoneNumber   = "/passport/v1/public/phoneNumber"
	pathSMS           = "/passport/v1/auth/sms"
	pathOnlineInfo    = "/passport/v1/user/onlineInfo"
	pathLogout        = "/passport/v1/user/logout"
	pathResource      = "/controller/v1/user/clientResource"
	pathQueryDevice   = "/passport/v1/security/queryDevice"
	pathTrustDevice   = "/passport/v1/security/trustDevice"
	pathUntrustDevice = "/passport/v1/security/untrustDevice"
)

// clientIdentity 是发给服务端的客户端标识。
//
// 它只影响终端记录里显示的设备名，不参与鉴权：换成中性标识后登录、
// 授信、隧道全部照常。仓库因此不需要出现任何厂商或产品字眼。
const clientIdentity = "njuvpn"
const maxControlBytes = 8 << 20

// 服务端用来区分客户端与平台的两个固定参数。
func withSharedParams(extra url.Values) url.Values {
	out := url.Values{"clientType": {"SDPClient"}, "platform": {"Linux"}, "lang": {"en-US"}}
	for k, v := range extra {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// 服务端错误码。只列会用到的：其余一律按"被拒绝"处理。
//
// 只有 75500002 有依据（五家参考实现里唯一被命名定义的一个：SID 过期后各
// 接口一律回它、重试无法修复，另有我们自己的实测记录）。其余几个码不能凭
// 字面猜含义：
//   - 75500000 是重载码：口令错误（实测）、需要图形验证码、反重放随机数过期
//     都用它，只能结合接口与 message 解释，所以口令那一步单独走 envelopeDataAuth；
//   - 75500401"冷却期内重复请求短信、不算失败"被三家参考实现一致采用，沿用；
//   - 75500001 / 75500005 / 75500006 在参考实现与实机记录里都没有定义或来源，
//     所以一律按通用拒绝处理：猜成"会话失效"会让用户被登出、猜成"账号已在别处
//     登录"会指错方向；未知码只输出数值，不传递任意服务端文案。
const (
	codeOK             = 0
	codeSessionGone    = 75500002 // 会话失效
	codeSMSAlreadySent = 75500401 // 冷却期内重复请求短信：不算失败
)

// control 是控制面客户端。它只负责发请求、解析响应、把服务端错误码
// 翻译成本包的错误类型；状态机在 session.go。
type control struct {
	server   string // Host 头与 SNI 用的名字
	dialAddr string // 实际连接地址（server_ip 或 server:port）
	dial     dial.DialFunc

	hc        *http.Client
	csrf      string
	deviceID  string
	pubKeyHex string
	pubKeyExp string
	debug     func(string)
}

type controlOptions struct {
	Server   string
	DialAddr string
	Dial     dial.DialFunc
	DeviceID string
	Debug    func(string)
	// InsecureSkipVerify 关闭证书校验；默认 false，也就是走系统信任链。
	InsecureSkipVerify bool
}

// controlTimeout 是控制面单次请求的整体上限（连接、TLS 与响应都算在内）。
const controlTimeout = 20 * time.Second

func newControl(opts controlOptions) (*control, error) {
	if opts.Dial == nil {
		return nil, fmt.Errorf("缺少拨号实现")
	}
	if opts.Server == "" || opts.DialAddr == "" {
		return nil, fmt.Errorf("缺少服务端地址")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	c := &control{
		server:   opts.Server,
		dialAddr: opts.DialAddr,
		dial:     opts.Dial,
		deviceID: opts.DeviceID,
		debug:    opts.Debug,
	}
	c.hc = &http.Client{
		Jar:     jar,
		Timeout: controlTimeout,
		// 不给跳转留空间：这条通道带着口令密文与 x-sdp-env、x-csrf-token
		// 这些自定义头，而 Go 只对 Authorization/Cookie 一类做跨主机剥离，
		// 307/308 连 body 一起重放。非 2xx 一律交给 do() 当失败。
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			// 默认走系统信任链：门户证书由公共 CA 签发，链与名称都能校验，
			// 口令与验证码因此不会交给路上的中间人（ServerName 由 URL 的主机名
			// 推导，即使实际连的是 server_ip 也按门户域名校验）。
			TLSClientConfig: &tls.Config{InsecureSkipVerify: opts.InsecureSkipVerify},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialWithContext(ctx, opts.Dial, network, opts.DialAddr)
			},
		},
	}
	return c, nil
}

func dialWithContext(ctx context.Context, fn dial.DialFunc, network, addr string) (net.Conn, error) {
	conn, err := fn(ctx, network, addr)
	if ctx.Err() != nil {
		if conn != nil {
			conn.Close()
		}
		return nil, ctx.Err()
	}
	return conn, dial.Wrap("拨号", err)
}

func (c *control) cookies() []*http.Cookie {
	u, _ := url.Parse("https://" + c.server)
	return c.hc.Jar.Cookies(u)
}

// do 发一个控制面请求。body 为 nil 表示不带请求体。
func (c *control) do(ctx context.Context, method, path string, params url.Values, body []byte, headers map[string]string) ([]byte, error) {
	target := "https://" + c.server + path
	if params != nil {
		target += "?" + params.Encode()
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", clientIdentity)
	if body != nil {
		req.Header.Set("Content-Type", "application/json;charset=utf-8")
	}
	if c.csrf != "" {
		req.Header.Set("x-csrf-token", c.csrf)
	}
	req.Header.Set("x-sdp-rid", base64.StdEncoding.EncodeToString([]byte(c.server)))
	traceID, err := randHex(8)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-sdp-traceid", traceID)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, dial.Wrap("控制面请求", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxControlBytes+1))
	if err != nil {
		return nil, dial.Wrap("读取控制面响应", err)
	}
	if len(raw) > maxControlBytes {
		return nil, &ProtocolError{What: "控制面响应超过 8 MiB"}
	}
	if c.debug != nil {
		c.debug(fmt.Sprintf("%s %s -> HTTP %d, %d 字节", method, path, resp.StatusCode, len(raw)))
	}
	if resp.StatusCode != http.StatusOK {
		return raw, fmt.Errorf("%s %s: HTTP %d", method, path, resp.StatusCode)
	}
	return raw, nil
}

// envelopeData 解析控制面响应：解信封、检查 code，会话类错误码按"会话已失效"
// 处理。
func envelopeData(raw []byte) (json.RawMessage, error) {
	return decodeEnvelope(raw, true)
}

// envelopeDataAuth 解析"这次登录到底成不成"这一步的响应。
//
// 实测：口令错误时服务端回的正是 75500000（HTTP 200 + 该错误码，文案是
// "The username or password is incorrect. You still have N attempts left"）。
// 那个码在别的接口上表示会话过期，在这里却是凭据不对——按会话失效处理会
// 让用户看到"会话已失效"并拿到 500，完全指不到问题所在，所以这一步单独
// 按"被拒绝"归类。
func envelopeDataAuth(raw []byte) (json.RawMessage, error) {
	return decodeEnvelope(raw, false)
}

// decodeEnvelope 是上面两个函数的公共实现。sessionCodes 为真时，唯一的
// 会话失效码（75500002）翻成 ErrSessionGone；其余码一律当作"被拒绝"，
// 服务端的任意 message 不进入错误或日志。
func decodeEnvelope(raw []byte, sessionCodes bool) (json.RawMessage, error) {
	var e envelope
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, &ProtocolError{What: "控制面响应不是 JSON"}
	}
	switch {
	case e.Code == nil:
		return nil, &ProtocolError{What: "控制面响应缺少整数 code"}
	case *e.Code == codeOK:
		if len(e.Data) == 0 || string(e.Data) == "null" {
			return nil, &ProtocolError{What: "控制面响应缺少 data"}
		}
		return e.Data, nil
	case sessionCodes && *e.Code == codeSessionGone:
		return nil, &ErrSessionGone{Code: *e.Code}
	default:
		return nil, &ErrCodeRejected{Code: *e.Code}
	}
}

// manifest 读服务端信息，当前只用作"控制面是否可达"的一次试探。
//
// 返回的版本与能力字段没有消费者——以前把它们解析进一个结构体再丢掉，
// 只留下一份"看起来有人在读"的假象。这里只校验它确实是 JSON 外壳：
// 网关的登录页与错误页也会回 200。
func (c *control) manifest(ctx context.Context) error {
	raw, err := c.do(ctx, http.MethodGet, pathManifest, nil, nil, nil)
	if err != nil {
		return err
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return &ProtocolError{What: "manifest 解析失败"}
	}
	return nil
}

// authMethod 是服务端下发的一种可用登录方式。
type authMethod struct {
	LoginDomain string `json:"loginDomain"`
	AuthType    string `json:"authType"`
	SubType     string `json:"subType"`
	AuthName    string `json:"authName"`
	AuthID      string `json:"authId"`
}

// authConfig 是一次 authConfig 请求的结果。
type authConfig struct {
	Methods        []authMethod
	IsLogin        bool
	PubKey         string
	PubKeyExp      string
	AntiReplayRand string
}

func (c *control) authConfig(ctx context.Context, needTicket bool) (authConfig, error) {
	var out authConfig
	params := withSharedParams(nil)
	if needTicket {
		params.Set("needTicket", "1")
	}
	raw, err := c.do(ctx, http.MethodGet, pathAuthConfig, params, nil, nil)
	if err != nil {
		return out, err
	}
	data, err := envelopeData(raw)
	if err != nil {
		return out, err
	}
	var d struct {
		AuthServerInfoList []authMethod `json:"authServerInfoList"`
		IsLogin            int          `json:"isLogin"`
		CSRF               string       `json:"csrfToken"`
		Security           struct {
			CSRF string `json:"csrfToken"`
		} `json:"security"`
		PubKey         string `json:"pubKey"`
		PubKeyExp      string `json:"pubKeyExp"`
		AntiReplayRand string `json:"antiReplayRand"`
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return out, &ProtocolError{What: "authConfig 解析失败"}
	}
	csrf := d.CSRF
	if csrf == "" {
		csrf = d.Security.CSRF
	}
	c.csrf = csrf
	c.pubKeyHex = d.PubKey
	c.pubKeyExp = d.PubKeyExp
	out.Methods = d.AuthServerInfoList
	out.IsLogin = d.IsLogin == 1
	out.PubKey = d.PubKey
	out.PubKeyExp = d.PubKeyExp
	out.AntiReplayRand = d.AntiReplayRand
	return out, nil
}

// passwordResult 是口令登录成功后的材料。
type passwordResult struct {
	Ticket         string
	NextService    string
	AntiReplayRand string
	GraphCheckCode bool
}

func (c *control) passwordLogin(ctx context.Context, username, password, domain, antiReplayRand string) (passwordResult, error) {
	var out passwordResult
	pub, err := parseRSAPublicKey(c.pubKeyHex, c.pubKeyExp)
	if err != nil {
		return out, err
	}
	encrypted, err := encryptPassword(pub, password+"_"+antiReplayRand)
	if err != nil {
		return out, err
	}
	body, err := json.Marshal(map[string]any{
		"username":    username + "@" + domain,
		"password":    encrypted,
		"rememberPwd": "0",
	})
	if err != nil {
		return out, err
	}
	envJSON, err := json.Marshal(map[string]string{"deviceId": c.deviceID})
	if err != nil {
		return out, err
	}
	env := base64.StdEncoding.EncodeToString(envJSON)
	raw, err := c.do(ctx, http.MethodPost, pathPasswordLogin, withSharedParams(nil), body,
		map[string]string{"x-sdp-env": env})
	if err != nil {
		return out, err
	}
	data, err := envelopeDataAuth(raw)
	if err != nil {
		return out, err
	}
	var d struct {
		Ticket               string `json:"ticket"`
		NextService          string `json:"nextService"`
		AntiReplayRand       string `json:"antiReplayRand"`
		GraphCheckCodeEnable int    `json:"graphCheckCodeEnable"`
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return out, &ProtocolError{What: "口令登录响应解析失败"}
	}
	out.Ticket = d.Ticket
	if out.Ticket == "" || len(out.Ticket) > 4096 {
		return out, &ProtocolError{What: "口令登录缺少有效 ticket"}
	}
	out.NextService = d.NextService
	out.AntiReplayRand = d.AntiReplayRand
	out.GraphCheckCode = d.GraphCheckCodeEnable == 1
	return out, nil
}

func (c *control) reportEnv(ctx context.Context, ticket string) error {
	body, err := json.Marshal(map[string]any{
		"ticket":   ticket,
		"deviceId": c.deviceID,
		"env": map[string]any{
			"endpoint": map[string]any{
				"device_id": c.deviceID,
				"device":    map[string]any{"type": "browser"},
			},
		},
	})
	if err != nil {
		return err
	}
	raw, err := c.do(ctx, http.MethodPost, pathReportEnv, withSharedParams(nil), body, nil)
	if err != nil {
		return err
	}
	_, err = envelopeData(raw)
	return err
}

// authStep 是认证链的下一步。
type authStep struct {
	Service string
	AuthID  string
}

// authStepFromData 解析 nextService / nextServiceList。
//
// 服务端可能只给 authId 不给 authType（短信二次验证的旧形态），
// 这时按短信处理。
func authStepFromData(data json.RawMessage) (authStep, error) {
	var d struct {
		NextService     string `json:"nextService"`
		NextServiceList []struct {
			AuthType string `json:"authType"`
			AuthID   string `json:"authId"`
		} `json:"nextServiceList"`
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &d); err != nil {
			return authStep{}, &ProtocolError{What: "认证链响应解析失败"}
		}
	}
	step := authStep{Service: d.NextService}
	for _, s := range d.NextServiceList {
		if step.Service != "" && s.AuthType == step.Service {
			step.AuthID = s.AuthID
			break
		}
		if step.AuthID == "" {
			step.AuthID = s.AuthID
		}
	}
	if step.Service == "auth/sendSms" {
		step.Service = "auth/sms"
	}
	if step.Service == "" && step.AuthID != "" {
		step.Service = "auth/sms"
	}
	return step, nil
}

func (c *control) authCheck(ctx context.Context) (authStep, error) {
	raw, err := c.do(ctx, http.MethodGet, pathAuthCheck, withSharedParams(nil), nil, nil)
	if err != nil {
		return authStep{}, err
	}
	data, err := envelopeData(raw)
	if err != nil {
		return authStep{}, err
	}
	return authStepFromData(data)
}

func (c *control) phoneNumber(ctx context.Context, authID string) ([]string, error) {
	params := withSharedParams(nil)
	if authID != "" {
		params.Set("authId", authID)
	}
	raw, err := c.do(ctx, http.MethodGet, pathPhoneNumber, params, nil, nil)
	if err != nil {
		return nil, err
	}
	data, err := envelopeData(raw)
	if err != nil {
		return nil, err
	}
	var d struct {
		PhoneNumber         json.RawMessage `json:"phoneNumber"`
		MaskIdentifierValue string          `json:"maskIdentifierValue"`
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, &ProtocolError{What: "手机号响应解析失败"}
	}
	var out []string
	if len(d.PhoneNumber) > 0 && d.PhoneNumber[0] == '[' {
		_ = json.Unmarshal(d.PhoneNumber, &out)
	} else if len(d.PhoneNumber) > 0 {
		var one string
		if err := json.Unmarshal(d.PhoneNumber, &one); err == nil && one != "" {
			out = append(out, one)
		}
	}
	if len(out) == 0 && d.MaskIdentifierValue != "" {
		out = append(out, d.MaskIdentifierValue)
	}
	return out, nil
}

// sendSMS 触发短信。返回给用户看的提示文案。
func (c *control) sendSMS(ctx context.Context, authID string, withAuthID bool) (string, error) {
	params := withSharedParams(url.Values{"action": {"sendsms"}})
	if withAuthID {
		params.Set("isPrevEffect", "0")
		params.Set("taskId", "")
		params.Set("authId", authID)
	}
	raw, err := c.do(ctx, http.MethodGet, pathSMS, params, nil, nil)
	if err != nil {
		return "", err
	}
	var e struct {
		Code    *int   `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Tips string `json:"tips"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &e); err != nil {
		return "", &ProtocolError{What: "短信响应解析失败"}
	}
	// 冷却期内重复请求返回的是上一次的响应，不算失败。
	if e.Code == nil {
		return "", &ProtocolError{What: "短信响应缺少整数 code"}
	}
	if *e.Code != codeOK && *e.Code != codeSMSAlreadySent {
		return "", &ErrCodeRejected{Code: *e.Code}
	}
	return "验证码已发送，请检查短信", nil
}

func (c *control) submitSMS(ctx context.Context, authID string, withAuthID bool, code string) (authStep, error) {
	params := withSharedParams(url.Values{"action": {"checkcode"}})
	var body []byte
	var headers map[string]string
	var err error
	if withAuthID {
		body, err = json.Marshal(map[string]any{
			"isPrevEffect":      false,
			"code":              code,
			"skipSecondaryAuth": "0",
			"taskId":            "",
			"authId":            authID,
		})
	} else {
		// 旧形态（服务端不给 authId）提交的是表单，Content-Type 必须跟着改：
		// do() 默认给带体的请求设 JSON，按 Content-Type 分派的网关会直接拒收。
		form := url.Values{"code": {code}, "skipSecondaryAuth": {"0"}}
		body = []byte(form.Encode())
		headers = map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	}
	if err != nil {
		return authStep{}, err
	}
	raw, err := c.do(ctx, http.MethodPost, pathSMS, params, body, headers)
	if err != nil {
		return authStep{}, err
	}
	data, err := envelopeData(raw)
	if err != nil {
		return authStep{}, err
	}
	return authStepFromData(data)
}

type onlineInfo struct {
	Username string
}

func (c *control) onlineInfo(ctx context.Context) (onlineInfo, error) {
	var out onlineInfo
	raw, err := c.do(ctx, http.MethodGet, pathOnlineInfo, withSharedParams(nil), nil, nil)
	if err != nil {
		return out, err
	}
	data, err := envelopeData(raw)
	if err != nil {
		return out, err
	}
	var d struct {
		Username string `json:"username"`
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return out, &ProtocolError{What: "在线信息解析失败"}
	}
	out.Username = d.Username
	return out, nil
}

func (c *control) clientResource(ctx context.Context) ([]byte, error) {
	body, err := json.Marshal(map[string]any{
		"resourceType": map[string]any{
			"sdpPolicy":       struct{}{},
			"appList":         struct{}{},
			"favoriteAppList": struct{}{},
			"featureCenter":   struct{}{},
			"uemSpace":        map[string]any{"params": map[string]string{"action": "login"}},
		},
	})
	if err != nil {
		return nil, err
	}
	raw, err := c.do(ctx, http.MethodPost, pathResource, withSharedParams(nil), body, nil)
	if err != nil {
		return nil, err
	}
	if _, err := envelopeData(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func (c *control) logout(ctx context.Context) error {
	raw, err := c.do(ctx, http.MethodPost, pathLogout, withSharedParams(nil), []byte("{}"), nil)
	if err != nil {
		return err
	}
	_, err = envelopeData(raw)
	return err
}

// randHex 生成 n 个十六进制字符的请求追踪 id。
//
// 用 crypto/rand：同一个包里已经有它（randomSignKey），而 math/rand 的默认源
// 在并发下还要抢锁。熵源读不出来就报错——这个值没有可用的降级替代。
func randHex(n int) (string, error) {
	buf := make([]byte, (n+1)/2)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("生成请求追踪 id: %w", err)
	}
	return hex.EncodeToString(buf)[:n], nil
}
