//go:build !windows

package ipc

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestDialRejectsUnsafePathBeforeConnecting(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	endpoint := filepath.Join(dir, "fake.sock")
	ln, err := net.Listen("unix", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	os.Chmod(endpoint, 0600)
	os.Chmod(dir, 0777)
	if c, err := Dial(endpoint); !errors.Is(err, ErrUntrustedPeer) {
		if c != nil {
			c.Close()
		}
		t.Fatal("不安全目录仍被采纳", err)
	}
	os.Chmod(dir, 0700)
	os.Chmod(endpoint, 0666)
	if c, err := Dial(endpoint); !errors.Is(err, ErrUntrustedPeer) {
		if c != nil {
			c.Close()
		}
		t.Fatal("不安全端点仍被采纳", err)
	}
	os.Chmod(endpoint, 0600)
	link := filepath.Join(dir, "link.sock")
	if err := os.Symlink(endpoint, link); err != nil {
		t.Fatal(err)
	}
	if c, err := Dial(link); !errors.Is(err, ErrUntrustedPeer) {
		if c != nil {
			c.Close()
		}
		t.Fatal("链接端点仍被采纳", err)
	}
	if c, err := Dial(endpoint); err != nil {
		t.Fatal("真实本用户端点被拒绝", err)
	} else {
		c.Close()
	}
}
func TestConnectedPeerCredentialsAreReadFromOS(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	endpoint := filepath.Join(dir, "peer.sock")
	ln, err := Listen(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := Dial(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	raw, err := c.(*net.UnixConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var good, bad error
	if err := raw.Control(func(fd uintptr) {
		good = verifyPeerFD(fd, uint32(os.Getuid()))
		bad = verifyPeerFD(fd, uint32(os.Getuid())+1)
	}); err != nil {
		t.Fatal(err)
	}
	if good != nil || !errors.Is(bad, ErrUntrustedPeer) {
		t.Fatal("未使用已连接对象的内核身份", good, bad)
	}
}
func TestSecondListenerDoesNotReplaceLiveEndpoint(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	endpoint := filepath.Join(dir, "live.sock")
	a, err := Listen(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if b, err := Listen(endpoint); err == nil {
		b.Close()
		t.Fatal("第二个实例抢占活端点")
	}
	c, err := Dial(endpoint)
	if err != nil {
		t.Fatal("原端点被移除", err)
	}
	c.Close()
}

func TestEndpointLeasePreventsConcurrentStaleCleanup(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	endpoint := filepath.Join(dir, "stale.sock")
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: endpoint, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	stale.Close()
	os.Chmod(endpoint, 0600)
	before, _ := os.Lstat(endpoint)
	lease, err := claimEndpoint(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if ln, err := Listen(endpoint); err == nil {
		ln.Close()
		t.Fatal("租约被持有时仍清理并绑定端点")
	}
	after, err := os.Lstat(endpoint)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("没有租约仍移除了原端点", err)
	}
	lease.Close()
	ln, err := Listen(endpoint)
	if err != nil {
		t.Fatal("释放租约后不能接管残留端点", err)
	}
	ln.Close()
}
