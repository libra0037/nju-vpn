package ztna

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestControlPlaneTreatsRedirectAsFailure 验证控制面把 3xx 当失败，而不是跟过去。
//
// 生产上这条通道的目标地址是钉住的（transport 永远拨 DialAddr），跳转打不到
// 别的主机；要钉的是另一半：3xx 必须以失败收场，而不是被跟着重放——重放会把
// 口令密文与 x-sdp-env、x-csrf-token 再发一遍，而且跟着走多远由对端说了算。
func TestControlPlaneTreatsRedirectAsFailure(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://vpn.example/passport/v1/auth/psw", http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	u, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	c, err := newControl(controlOptions{
		Server: u.Hostname(), DialAddr: u.Host,
		Dial: func(network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.Dial(network, addr)
		},
		// 生产走系统信任链；这里对着自签的测试服务端，显式关掉。
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = c.do(ctx, http.MethodPost, "/passport/v1/auth/psw", nil, []byte("{}"), nil)
	if err == nil {
		t.Fatal("307 应当被当成失败")
	}
	if !strings.Contains(err.Error(), "HTTP 307") {
		t.Fatalf("失败原因应当是 307 本身（而不是跟着跳转之后的别的东西），得到 %v", err)
	}
}
