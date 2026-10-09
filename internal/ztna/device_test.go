package ztna

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestUntrustSelectsOnlyValidDeviceIDsAndVerifiesResult(t *testing.T) {
	for _, tc := range []struct {
		name   string
		all    bool
		before string
		after  string
		ids    []string
		fail   bool
	}{
		{"id", false, `{"selfId":"self","deviceTrusted":true,"currentTrustDeviceCount":2,"data":[{"id":"other"},{"id":"self"}]}`, `{"selfId":"self","deviceTrusted":false,"currentTrustDeviceCount":1,"data":[{"id":"other"}]}`, []string{"self"}, false},
		{"dev-db-id", false, `{"selfId":"self","deviceTrusted":true,"currentTrustDeviceCount":2,"data":[{"id":"other"},{"devDbId":"self"}]}`, `{"selfId":"self","deviceTrusted":false,"currentTrustDeviceCount":1,"data":[{"id":"other"}]}`, []string{"self"}, false},
		{"both-ids", false, `{"selfId":"self","deviceTrusted":true,"currentTrustDeviceCount":1,"data":[{"id":"record","devDbId":"self"}]}`, `{"selfId":"self","deviceTrusted":false,"currentTrustDeviceCount":0,"data":[]}`, []string{"record"}, false},
		{"query-self-id", false, `{"selfId":"self","deviceTrusted":true,"currentTrustDeviceCount":1,"data":[{}]}`, `{"selfId":"self","deviceTrusted":false,"currentTrustDeviceCount":0,"data":[]}`, []string{"self"}, false},
		{"missing-self-id", false, `{"selfId":"","deviceTrusted":true,"currentTrustDeviceCount":1,"data":[{"id":"other"}]}`, "", nil, true},
		{"already-untrusted-without-id", false, `{"selfId":"","deviceTrusted":false,"currentTrustDeviceCount":1,"data":[{"id":"other"}]}`, "", nil, false},
		{"all-ids", true, `{"selfId":"","deviceTrusted":false,"currentTrustDeviceCount":3,"data":[{"id":"one"},{"devDbId":"two"},{"id":"three","devDbId":"unused"}]}`, `{"deviceTrusted":false,"currentTrustDeviceCount":0,"data":[]}`, []string{"one", "two", "three"}, false},
		{"all-missing-ids", true, `{"deviceTrusted":false,"currentTrustDeviceCount":1,"data":[{}]}`, "", nil, true},
		{"local-still-trusted", false, `{"selfId":"self","deviceTrusted":true,"currentTrustDeviceCount":1,"data":[{"id":"self"}]}`, `{"selfId":"self","deviceTrusted":true,"currentTrustDeviceCount":1,"data":[{"id":"self"}]}`, []string{"self"}, true},
		{"all-still-trusted", true, `{"deviceTrusted":false,"currentTrustDeviceCount":1,"data":[{"id":"other"}]}`, `{"deviceTrusted":false,"currentTrustDeviceCount":1,"data":[{"id":"other"}]}`, []string{"other"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var sent []string
			queries, posts := 0, 0
			var mu sync.Mutex
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/passport/v1/security/queryDevice":
					if r.Method != http.MethodGet || r.URL.Query().Get("status") != "trust" {
						t.Error("设备查询契约错误")
					}
					mu.Lock()
					body := tc.before
					if queries > 0 {
						body = tc.after
					}
					queries++
					mu.Unlock()
					io.WriteString(w, `{"code":0,"data":`+body+`}`)
				case "/passport/v1/security/untrustDevice":
					var body struct {
						IDs []string `json:"idList"`
					}
					if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&body) != nil {
						t.Error("撤信请求契约错误")
					}
					mu.Lock()
					posts++
					sent = body.IDs
					mu.Unlock()
					io.WriteString(w, `{"code":0,"data":{}}`)
				default:
					t.Error("未预期的控制请求")
					w.WriteHeader(http.StatusBadRequest)
				}
			}))
			t.Cleanup(server.Close)
			d := &DeviceSession{sess: &Session{ctrl: &control{server: strings.TrimPrefix(server.URL, "https://"), hc: server.Client()}}}
			st, err := d.Untrust(context.Background(), tc.all)
			mu.Lock()
			defer mu.Unlock()
			var protocol *ProtocolError
			if (err != nil) != tc.fail || tc.fail && !errors.As(err, &protocol) {
				t.Fatal("撤信结果类别错误", st, err)
			}
			if !reflect.DeepEqual(sent, tc.ids) {
				t.Fatal("发送了错误或空设备标识", sent, tc.ids)
			}
			wantPosts, wantQueries := 0, 1
			if len(tc.ids) != 0 {
				wantPosts, wantQueries = 1, 2
			}
			if posts != wantPosts || queries != wantQueries {
				t.Fatal("撤信请求或结果核验次数错误", posts, queries)
			}
			if !tc.fail && (st.Trusted || tc.all && (st.Count != 0 || len(st.Devices) != 0)) {
				t.Fatal("仍有授信却报告操作成功", st)
			}
		})
	}
}
