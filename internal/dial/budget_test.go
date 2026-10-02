package dial

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestHTTPConnectRejectsOversizedResponseHeader(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		response := "HTTP/1.1 200 Connection Established\r\n" + strings.Repeat("X-Fill: "+strings.Repeat("a", 256)+"\r\n", 80) + "\r\n"
		io.WriteString(c, response)
	}()
	fn, err := New("http://" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	c, err := fn(ctx, "tcp", "vpn.test:443")
	if c != nil {
		c.Close()
	}
	if err == nil {
		t.Fatal("CONNECT 超限响应头仍接受")
	}
	ln.Close()
	<-done
}
