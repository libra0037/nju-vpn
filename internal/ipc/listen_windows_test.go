package ipc

import (
	"errors"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestNamedPipeServerSIDComesFromConnectedProcess(t *testing.T) {
	endpoint := EndpointFor(filepath.Join(t.TempDir(), "pipe.yaml"))
	ln, err := Listen(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			var b [1]byte
			c.Read(b[:])
		}
	}()
	c, err := Dial(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		c.Close()
		t.Fatal(err)
	}
	if err := verifyPipeServer(c, current.User.Sid); err != nil {
		c.Close()
		t.Fatal(err)
	}
	system, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		c.Close()
		t.Fatal(err)
	}
	if !current.User.Sid.Equals(system) && !errors.Is(verifyPipeServer(c, system), ErrUntrustedPeer) {
		c.Close()
		t.Fatal("把管道名或 DACL 当成服务身份")
	}
	if !errors.Is(verifyPipeServer(c, nil), ErrUntrustedPeer) {
		c.Close()
		t.Fatal("缺少期望身份仍通过")
	}
	c.Close()
	<-done
}
