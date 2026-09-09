package vpn

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
)

// 登出相关的状态。
var (
	// ErrLogoutNoSession 表示服务端没有找到可登出的会话。
	ErrLogoutNoSession = errors.New("服务端没有该会话")
)

// Logout 通知服务端结束当前会话。
//
// 服务端用 GET /por/logout.csp 携带有效 TWFID 来注销。成功返回
// "logout user success"；TWFID 已失效时返回 "logout user failed"。
//
// 这一步很重要：服务端对同一账号的隧道会话数有限制，本地直接关闭连接
// 不会释放服务端侧的名额，长期会累积到无法再建隧道。
func (client *Client) Logout(twfId string) error {
	if twfId == "" {
		return errors.New("TWFID 为空，无法登出")
	}

	c := client.httpClient()
	addr := "https://" + client.server + "/por/logout.csp"

	req, err := http.NewRequest("GET", addr, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Cookie", "TWFID="+twfId)

	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("请求登出接口: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return fmt.Errorf("读取登出响应: %w", err)
	}

	return classifyLogout(body)
}

// classifyLogout 解析登出响应。
func classifyLogout(body []byte) error {
	s := string(body)

	if m := regexp.MustCompile(`<Message><!\[CDATA\[(.*?)\]\]></Message>`).FindStringSubmatch(s); m != nil {
		msg := m[1]
		log.Printf("登出响应: %s", msg)
		switch {
		case msg == "logout user success":
			return nil
		case msg == "logout user failed":
			return ErrLogoutNoSession
		default:
			return fmt.Errorf("登出失败: %s", msg)
		}
	}
	return fmt.Errorf("登出响应无法解析: %s", serverMessage(body))
}
