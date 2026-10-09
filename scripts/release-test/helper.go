//go:build ignore

// 独立测试包的辅助工具；不加入产品命令或发布产物。
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/libra0037/nju-vpn/internal/config"
	"github.com/libra0037/nju-vpn/internal/ipc"
	"github.com/libra0037/nju-vpn/internal/wireguard"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "测试辅助工具:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return errors.New("用法: test-helper info|new-peer|state|resources|shutdown -config <path> [-out <目录>]")
	}
	command := os.Args[1]
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	path := fs.String("config", "", "测试配置路径")
	out := fs.String("out", "", "测试对端密钥目录")
	if err := fs.Parse(os.Args[2:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("不接受位置参数")
	}
	if command == "new-peer" {
		if *out == "" {
			return errors.New("必须指定 -out")
		}
		key, err := wireguard.GenerateKey()
		if err != nil {
			return err
		}
		pub, err := key.PublicKey()
		if err != nil {
			return err
		}
		if err := os.MkdirAll(*out, 0700); err != nil {
			return err
		}
		f, err := os.OpenFile(filepath.Join(*out, "peer.key"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, writeErr := fmt.Fprintln(f, key.String())
		closeErr := f.Close()
		if err := errors.Join(writeErr, closeErr); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"public_key": pub.String()})
	}
	if *path == "" {
		return errors.New("必须指定 -config")
	}
	if command == "info" {
		cfg, err := config.Load(*path)
		if err != nil {
			return err
		}
		public := ""
		if cfg.WireGuard.PrivateKey != "" {
			key, err := wireguard.ParseKey(cfg.WireGuard.PrivateKey)
			if err != nil {
				return err
			}
			pub, err := key.PublicKey()
			if err != nil {
				return err
			}
			public = pub.String()
		}
		identity, _ := json.Marshal([]any{cfg.DeviceID, cfg.WireGuard.PrivateKey, cfg.PinnedNodeSPKISHA256, cfg.WireGuard.PeerPublicKey, cfg.WireGuard.MTU})
		hash := sha256.Sum256(identity)
		return json.NewEncoder(os.Stdout).Encode(map[string]any{
			"public_key": public, "peer_public_key": cfg.WireGuard.PeerPublicKey,
			"peer_address": cfg.WireGuard.PeerAddress, "listen_port": cfg.WireGuard.ListenPort,
			"listen_host": cfg.WireGuard.ListenHost, "mtu": cfg.WireGuard.MTU,
			"wireguard_enabled": cfg.WireGuard.Enabled, "socks5_enabled": cfg.SOCKS5.Enabled,
			"identity_sha256": hex.EncodeToString(hash[:]), "password_set": cfg.Password != "",
		})
	}
	if command != "state" && command != "resources" && command != "shutdown" {
		return errors.New("未知的测试操作")
	}
	response, err := ipc.NewClient(*path).Call(ipc.Request{Command: command}, 30*time.Second)
	if err != nil {
		return err
	}
	if response.Code != ipc.CodeOK {
		return fmt.Errorf("IPC 操作失败，状态码 %d", response.Code)
	}
	if command == "resources" {
		var resources ipc.Resources
		if err := json.Unmarshal([]byte(response.Message), &resources); err != nil {
			return errors.New("资源快照格式非法")
		}
		if err := resources.Validate(); err != nil {
			return err
		}
		hash := sha256.Sum256([]byte(response.Message))
		return json.NewEncoder(os.Stdout).Encode(map[string]any{
			"ip_rules": len(resources.IP), "tcp_domains": len(resources.TCPDomains), "json_bytes": len(response.Message),
			"sha256": hex.EncodeToString(hash[:]),
		})
	}
	_, err = fmt.Fprintln(os.Stdout, response.Message)
	return err
}
