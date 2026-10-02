package dial

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
)

func TestEarlyCloseErrorIsDiagnosableAndRedacted(t *testing.T) {
	for _, cause := range []error{io.EOF, io.ErrUnexpectedEOF} {
		inner := &net.OpError{Op: "read", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 23), Port: 441}, Err: cause}
		err := Wrap("探测隧道节点", Wrap("隧道节点 TLS 握手", inner))
		if got := err.Error(); got != "探测隧道节点失败（对端提前关闭连接）" {
			t.Fatal("丢失安全的失败原因", got)
		}
		if !errors.Is(err, cause) {
			t.Fatal("丢失底层错误类别")
		}
	}
	err := Wrap("连接目标", errors.New("private-address secret-password"))
	if strings.Contains(err.Error(), "private-address") || strings.Contains(err.Error(), "secret-password") {
		t.Fatal("未知错误回显了原始值")
	}
}
