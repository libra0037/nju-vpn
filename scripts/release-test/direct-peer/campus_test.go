package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/libra0037/nju-vpn/internal/config"
	"github.com/libra0037/nju-vpn/internal/ipc"
	"github.com/libra0037/nju-vpn/internal/socks5"
	"github.com/libra0037/nju-vpn/internal/ztna"
	"gopkg.in/yaml.v3"
)

func TestCampusPreparePreservesPrivateSourceAndHandlesSOCKSOnly(t *testing.T) {
	for _, sourceEnabled := range []bool{false, true} {
		t.Run(strconv.FormatBool(sourceEnabled), func(t *testing.T) {
			cfg := &config.Config{
				Server: "test.invalid", Username: "test-account", Password: "  opaque:秘密 $`  ", DeviceID: "existing-device",
				Proxy: "http://127.0.0.1:9123", PinnedNodeSPKISHA256: []string{base64.StdEncoding.EncodeToString(make([]byte, 32))},
				WireGuard: config.WireGuard{Enabled: sourceEnabled, ListenPort: 51822, MTU: 1280, ListenHost: "all", PeerAddress: "10.66.66.2"},
				SOCKS5:    config.SOCKS5{Enabled: true, ListenPort: 1089, ListenHost: "all", Username: "user", Password: "  proxy secret  ", MaxConnections: 1, MaxDials: 1},
			}
			body, err := yaml.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(t.TempDir(), "original.yaml")
			if err := os.WriteFile(source, body, 0600); err != nil {
				t.Fatal(err)
			}
			loaded, err := config.LoadForClient(source)
			if err != nil {
				t.Fatal(err)
			}
			before := *loaded
			out := filepath.Join(t.TempDir(), "private-campus")
			if err := prepareCampus(loaded, out); err != nil {
				t.Fatal(err)
			}
			prepared, err := config.LoadForClient(filepath.Join(out, "config.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			key, err := readKey(filepath.Join(out, "peer.key"))
			if err != nil {
				t.Fatal(err)
			}
			pub, err := key.PublicKey()
			if err != nil || prepared.WireGuard.PeerPublicKey != pub.String() || prepared.WireGuard.PrivateKey == "" ||
				!prepared.WireGuard.Enabled || prepared.WireGuard.MTU != 1400 || prepared.WireGuard.ListenHost != "loopback" ||
				!prepared.SOCKS5.Enabled || prepared.SOCKS5.ListenHost != "loopback" || prepared.SOCKS5.MaxConnections != 8 || prepared.SOCKS5.MaxDials != 4 ||
				prepared.Password != before.Password || prepared.DeviceID != before.DeviceID || prepared.Proxy != before.Proxy || prepared.Username != before.Username ||
				prepared.SOCKS5.Password != before.SOCKS5.Password || prepared.SOCKS5.Username != before.SOCKS5.Username || !reflect.DeepEqual(prepared.PinnedNodeSPKISHA256, before.PinnedNodeSPKISHA256) {
				t.Fatal("测试参数、凭据或身份没有按契约准备")
			}
			if !reflect.DeepEqual(before, *loaded) {
				t.Fatal("共享源配置对象被修改")
			}
			after, err := os.ReadFile(source)
			if err != nil || !bytes.Equal(body, after) {
				t.Fatal("原文件被写回")
			}
			if err := prepareCampus(loaded, out); err == nil {
				t.Fatal("覆盖了已有私有目录")
			}
		})
	}
}

func TestCampusSessionRequiresUnchangedLoginAndEndpointState(t *testing.T) {
	before := campusStatus{State: "up", SessionReady: true, Since: time.Unix(100, 0)}
	before.Identity.PID = 123
	before.WireGuard.Enabled, before.WireGuard.Listening = true, true
	before.SOCKS5.Enabled, before.SOCKS5.Listening = true, true
	if !sameCampusSession(before, before, true, true) {
		t.Fatal("正常状态未通过")
	}
	for _, change := range []func(*campusStatus){
		func(s *campusStatus) { s.Identity.PID++ }, func(s *campusStatus) { s.Since = s.Since.Add(time.Second) },
		func(s *campusStatus) { s.State = "idle" }, func(s *campusStatus) { s.SessionReady = false },
		func(s *campusStatus) { s.WireGuard.Listening = false }, func(s *campusStatus) { s.SOCKS5.Enabled = false },
	} {
		after := before
		change(&after)
		if sameCampusSession(before, after, true, true) {
			t.Fatal("不同登录或错误端点状态被接受")
		}
	}
	after := before
	after.WireGuard.Enabled, after.WireGuard.Listening = false, false
	if !sameCampusSession(before, after, false, true) {
		t.Fatal("合法的单端点停止未通过")
	}
}

func TestCampusHalfCloseUsesEOFAndRejectsWrongContent(t *testing.T) {
	for _, tc := range []struct {
		name string
		auth bool
		size int
		bad  bool
		pass bool
	}{
		{"noauth", false, 1048576, false, true}, {"auth", true, 1048576, false, true},
		{"truncated", false, 1048575, false, false}, {"wrong-content", true, 1048576, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				c, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				body, err := io.ReadAll(io.LimitReader(c, 1048577))
				// 服务端先读到 EOF 才回应；完整 Close 会让客户端丢失下行。
				if err != nil || len(body) != 1048576 || !bytes.Equal(body[:256], []byte(allBytes)) {
					done <- errors.New("服务端未收到固定上传和 EOF")
					return
				}
				if tc.bad {
					body[0] ^= 1
				}
				_, err = c.Write(body[:tc.size])
				done <- err
			}()
			opts := socks5.Options{MaxConnections: 2, MaxDials: 1}
			if tc.auth {
				opts.Username, opts.Password = "test-user", "  test-secret  "
			}
			proxy, err := socks5.New("127.0.0.1:0", opts)
			if err != nil {
				t.Fatal(err)
			}
			proxyDone := make(chan error, 1)
			go func() {
				proxyDone <- proxy.Run(t.Context(), func(ctx context.Context, target ztna.TCPTarget) (socks5.Stream, error) {
					want, _ := ztna.NewTCPTarget("192.0.2.1", 18082)
					if target != want {
						return nil, errors.New("流量绕过了指定的 SOCKS 目标")
					}
					c, err := (&net.Dialer{}).DialContext(ctx, "tcp4", listener.Addr().String())
					if err != nil {
						return nil, err
					}
					return &proxyTestStream{c.(*net.TCPConn)}, nil
				})
			}()
			t.Cleanup(func() {
				proxy.Close()
				listener.Close()
				if err := <-proxyDone; err != nil {
					t.Error(err)
				}
				if err := <-done; err != nil {
					t.Error(err)
				}
			})
			<-proxy.Started()
			cfg := &config.Config{SOCKS5: config.SOCKS5{ListenPort: proxy.Diagnostics().Port, Username: opts.Username, Password: opts.Password}}
			r := probeSOCKSHalfClose(t.Context(), cfg, netip.MustParseAddrPort("192.0.2.1:18082"), 5*time.Second)
			if r.Passed != tc.pass || r.Bytes != int64(tc.size) {
				t.Fatal("半关闭或独立正文判据错误", r)
			}
		})
	}
}

func TestCampusSOCKSCancelClosesStalledHandshake(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		var greeting [3]byte
		if _, err := io.ReadFull(c, greeting[:]); err != nil || greeting != [3]byte{5, 1, 0} {
			done <- errors.New("协商固定字节错误")
			return
		}
		cancel()
		_, err = io.ReadAll(c)
		done <- err
	}()
	cfg := &config.Config{SOCKS5: config.SOCKS5{ListenPort: listener.Addr().(*net.TCPAddr).Port}}
	c, err := dialCampusSOCKS(ctx, cfg, netip.MustParseAddrPort("192.0.2.1:18082"))
	if err == nil {
		c.Close()
		t.Fatal("取消后仍返回可用连接")
	}
	if err := <-done; err != nil {
		t.Fatal("取消没有关闭真实握手连接", err)
	}
}

func TestCampusCloseWaitsAndStillShutsDownAfterStopFailure(t *testing.T) {
	for _, code := range []int{ipc.CodeOK, ipc.CodeServerError} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			listener, err := ipc.Listen(ipc.EndpointFor(path))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				for i, want := range []string{ipc.CmdStop, ipc.CmdShutdown} {
					c, err := listener.Accept()
					if err != nil {
						done <- err
						return
					}
					c.SetDeadline(time.Now().Add(time.Second))
					r := bufio.NewReader(c)
					ping, err := ipc.ReadRequest(r)
					if err != nil || ping.Command != ipc.CmdPing {
						c.Close()
						done <- errors.New("收尾没有先核验实例")
						return
					}
					body, _ := json.Marshal(ipc.InstanceIdentity{ConfigPath: ipc.ConfigIdentity(path)})
					if err := ipc.WriteResponse(c, ipc.Response{Code: ipc.CodeOK, Message: string(body)}); err != nil {
						c.Close()
						done <- err
						return
					}
					request, err := ipc.ReadRequest(r)
					if err != nil || request.Command != want || len(request.Args) != 0 {
						c.Close()
						done <- errors.New("收尾命令、顺序或参数错误")
						return
					}
					status := ipc.CodeOK
					if i == 0 {
						status = code
					} else {
						listener.Close()
					}
					err = ipc.WriteResponse(c, ipc.Response{Code: status})
					c.Close()
					if err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			if stopped := closeCampus(ctx, path); stopped != (code == ipc.CodeOK) {
				t.Fatal("收尾没有保留 stop 失败或没有等到端点消失")
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

// 独立固定样例，覆盖字节 0..255；不调用被测 payload 生成期望值。
const allBytes = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" +
	"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f" +
	"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f" +
	"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f" +
	"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f" +
	"\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f" +
	"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f" +
	"\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f" +
	"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f" +
	"\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f" +
	"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf" +
	"\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf" +
	"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf" +
	"\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf" +
	"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef" +
	"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
