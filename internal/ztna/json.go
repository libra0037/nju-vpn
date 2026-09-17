package ztna

import "encoding/json"

// envelope 是控制面与隧道信封里通用的响应外壳。
type envelope struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// parseEnvelopeCode 取响应码。第二个返回值为 false 表示不是 JSON 外壳。
func parseEnvelopeCode(payload []byte) (int, string, bool) {
	var e envelope
	if err := json.Unmarshal(payload, &e); err != nil {
		return 0, "", false
	}
	return e.Code, e.Message, true
}
