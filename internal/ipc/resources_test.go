package ipc

import (
	"errors"
	"testing"
)

func TestResourceEncodingCountsEscapesAndRejectsWholeResponse(t *testing.T) {
	r := Resources{IP: []IPResource{}, TCPDomains: []TCPDomainResource{{Pattern: "<x>\\\n", Ports: [2]uint16{443, 443}}}}
	const want = `{"ip":[],"tcpDomains":[{"pattern":"\u003cx\u003e\\\n","ports":[443,443]}],"dns":{"primary":"","secondary":""}}`
	body, err := EncodeResources(r, len(want))
	if err != nil || string(body) != want {
		t.Fatal("实际转义长度未遵守预算", string(body), err)
	}
	if body, err := EncodeResources(r, len(want)-1); body != nil || !errors.Is(err, ErrResourceSnapshotTooLarge) {
		t.Fatal("超限返回部分响应", err)
	}
	if err := r.Validate(); err == nil {
		t.Fatal("非法模式未拒绝")
	}
	empty := Resources{IP: []IPResource{}, TCPDomains: []TCPDomainResource{}}
	body, err = EncodeResources(empty, 100)
	if err != nil || string(body) != `{"ip":[],"tcpDomains":[],"dns":{"primary":"","secondary":""}}` {
		t.Fatal("空表格式错误", string(body), err)
	}
	if err := empty.Validate(); err != nil {
		t.Fatal(err)
	}
}
