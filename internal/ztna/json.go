package ztna

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// envelope 是控制面与隧道信封里通用的响应外壳。
type envelope struct {
	Code *int            `json:"code"`
	Data json.RawMessage `json:"data"`
}

// 在构造资源对象前限制嵌套与节点数；未知 JSON 字段也计入预算。
func validateJSON(raw []byte) error {
	if len(raw) > maxControlBytes {
		return &ProtocolError{What: "JSON 响应过长"}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	depth, count := 0, 0
	for {
		token, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return &ProtocolError{What: "JSON 响应格式非法"}
		}
		count++
		if d, ok := token.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
		if count > 200000 || depth > 32 {
			return &ProtocolError{What: "JSON 嵌套或节点数量超过上限"}
		}
	}
	return nil
}

// parseEnvelopeCode 取响应码。第二个返回值为 false 表示不是 JSON 外壳。
func parseEnvelopeCode(payload []byte) (int, string, bool) {
	var e envelope
	if err := json.Unmarshal(payload, &e); err != nil || e.Code == nil {
		return 0, "", false
	}
	return *e.Code, "", true
}
