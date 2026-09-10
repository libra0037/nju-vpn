// Package config 负责读取服务进程的配置文件。
package config

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config 是服务进程的全部可配置项。
type Config struct {
	// sourcePath 是这份配置的来源文件，用于把生成的内容写回原文件。
	sourcePath string

	Server string `yaml:"server"`
	// ServerIP 可选：服务端域名在本机解析不了时，直接连这个地址，
	// 协议层仍用 Server 生成 Host 头。
	ServerIP   string    `yaml:"server_ip"`
	Port       int       `yaml:"port"`
	Username   string    `yaml:"username"`
	Password   string    `yaml:"password"`
	TOTPSecret string    `yaml:"totp_secret"`
	Proxy      string    `yaml:"proxy"`
	WireGuard  WireGuard `yaml:"wireguard"`
	IPC        IPC       `yaml:"ipc"`
	MTU        int       `yaml:"mtu"`
	Log        Log       `yaml:"log"`
}

type WireGuard struct {
	ListenPort    int    `yaml:"listen_port"`
	PrivateKey    string `yaml:"private_key"`
	PeerPublicKey string `yaml:"peer_public_key"`
	PeerAddress   string `yaml:"peer_address"`
}

type IPC struct {
	Endpoint string `yaml:"endpoint"`
}

type Log struct {
	Level string `yaml:"level"`
}

// MTU 的允许区间。隧道自身的 MTU 是 1400，再减去 WireGuard 的封装开销，
// 留给承载层的空间不该超过这个上限；下限则取 IPv4 的最小可行值。
const (
	MinMTU = 576
	MaxMTU = 1400
)

// SourcePath 返回这份配置的来源文件路径。
func (c *Config) SourcePath() string { return c.sourcePath }

// DefaultPath 返回当前平台的默认配置文件路径。
func DefaultPath() string {
	if runtime.GOOS == "windows" {
		return `C:ProgramData
juvpnconfig.yaml`
	}
	return "/etc/njuvpn/config.yaml"
}

// Load 读取配置文件，供服务进程与探测命令使用。
//
// 会强制要求文件权限不允许同机其他用户读取：这个文件里有账号口令和
// TOTP 密钥，权限放宽等于把凭据交出去。
func Load(path string) (*Config, error) {
	cfg, err := load(path)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

// LoadForClient 读取命令行客户端需要的部分（只有 IPC 端点）。
//
// 它容忍配置文件不可读或权限过宽：CLI 根本不需要账号口令，
// 不该因为"读不到服务进程的凭据文件"而无法工作——那种情况下
// 退回默认端点即可。
func LoadForClient(path string) (*Config, error) {
	cfg, err := load(path)
	if err != nil {
		return &Config{}, err
	}
	return cfg, nil
}

func load(path string) (*Config, error) {
	if path == "" {
		path = DefaultPath()
	}

	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件 %s: %w", path, err)
	}
	if err := checkPermissions(path, fi); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件 %s: %w", path, err)
	}

	var cfg Config
	cfg.sourcePath = path
	// KnownFields 让键名写错时直接报错，而不是静默回落默认值。
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件 %s: %w", path, err)
	}
	cfg.applyDefaults()

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("配置文件 %s: %w", path, err)
	}
	return &cfg, nil
}

// checkPermissions 检查配置文件是否只对属主可读。
func checkPermissions(path string, fi os.FileInfo) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf(
			"配置文件 %s 的权限是 %04o，同机其他用户可以读到账号口令与 TOTP 密钥；请执行 chmod 600 %s",
			path, fi.Mode().Perm(), path)
	}
	return nil
}

func (c *Config) applyDefaults() {
	if c.Port == 0 {
		c.Port = 443
	}
	if c.MTU == 0 {
		c.MTU = 1320
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.WireGuard.ListenPort == 0 {
		c.WireGuard.ListenPort = 51820
	}
	if c.WireGuard.PeerAddress == "" {
		c.WireGuard.PeerAddress = "10.66.66.2"
	}
}

func (c *Config) validate() error {
	if c.Server == "" {
		return fmt.Errorf("缺少 server")
	}
	if err := validateHost("server", c.Server); err != nil {
		return err
	}
	if c.ServerIP != "" {
		if net.ParseIP(c.ServerIP) == nil {
			return fmt.Errorf("server_ip 不是合法地址: %q", c.ServerIP)
		}
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("port 超出范围: %d", c.Port)
	}
	if c.Username == "" {
		return fmt.Errorf("缺少 username")
	}
	if c.Password == "" {
		return fmt.Errorf("缺少 password")
	}
	if c.MTU < MinMTU || c.MTU > MaxMTU {
		return fmt.Errorf("mtu 超出范围: %d（应在 %d-%d 之间，1320 适合默认隧道）", c.MTU, MinMTU, MaxMTU)
	}
	if p := c.WireGuard.ListenPort; p < 1 || p > 65535 {
		return fmt.Errorf("wireguard.listen_port 超出范围: %d", p)
	}
	if ip := net.ParseIP(c.WireGuard.PeerAddress); ip == nil || ip.To4() == nil {
		return fmt.Errorf("wireguard.peer_address 必须是 IPv4 地址: %q", c.WireGuard.PeerAddress)
	}
	return nil
}

// Warnings 返回不影响启动、但用户应该知道的问题。
func (c *Config) Warnings() []string {
	var out []string
	if c.WireGuard.PeerPublicKey == "" {
		out = append(out, "未配置 wireguard.peer_public_key，任何客户端都无法接入")
	}
	if c.TOTPSecret == "" {
		out = append(out, "未配置 totp_secret，需要手工执行 njuvpn auth <code> 完成二次验证")
	}
	return out
}

// validateHost 检查目标主机名。写成 "host:port" 是最常见的错误：
// 端口是独立字段，拼起来会变成 "[host:port]:443"。
func validateHost(field, host string) error {
	if net.ParseIP(host) != nil {
		return nil
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return fmt.Errorf("%s 里带了端口: %q（端口请写在 port 字段）", field, host)
	}
	for _, r := range host {
		if r <= ' ' || r == '/' || r == '\\' {
			return fmt.Errorf("%s 含非法字符: %q", field, host)
		}
	}
	return nil
}

// PersistPrivateKey 把自动生成的 WireGuard 私钥写回配置文件。
//
// 就地替换 wireguard 段里的 private_key 行，保留原有的注释——用 YAML
// 序列化整份配置会把注释全部丢掉，而那份文件是给人看的。
// 找不到对应行时按情况插入或追加一段。
func PersistPrivateKey(path, key string) error {
	if path == "" {
		return fmt.Errorf("没有配置文件路径")
	}
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	sectionAt := -1  // wireguard: 所在行
	sectionEnd := -1 // wireguard 段的最后一行
	inSection := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		if indent == 0 {
			if inSection {
				sectionEnd = i - 1
				inSection = false
			}
			if strings.HasPrefix(trimmed, "wireguard:") {
				sectionAt = i
				sectionEnd = i
				inSection = true
			}
			continue
		}
		if !inSection {
			continue
		}
		sectionEnd = i
		if strings.HasPrefix(trimmed, "private_key:") {
			lines[i] = line[:indent] + "private_key: " + key
			return writePreservingMode(path, fi, lines)
		}
	}

	switch {
	case sectionAt >= 0:
		// 有 wireguard 段但没有 private_key 行，插到段尾。
		insertAt := sectionEnd + 1
		lines = append(lines[:insertAt], append([]string{"  private_key: " + key}, lines[insertAt:]...)...)
	default:
		// 完全没有 wireguard 段，追加一段。
		lines = append(lines, "wireguard:", "  private_key: "+key)
	}
	return writePreservingMode(path, fi, lines)
}

// writePreservingMode 写回文件并保持原有权限。
func writePreservingMode(path string, fi os.FileInfo, lines []string) error {
	content := strings.Join(lines, "\n")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), fi.Mode().Perm()); err != nil {
		return fmt.Errorf("写入 %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("替换 %s: %w", path, err)
	}
	return nil
}

// ServerAddr 返回 "host:port" 形式的目标地址。
func (c *Config) ServerAddr() string {
	return net.JoinHostPort(c.Server, strconv.Itoa(c.Port))
}

// DialAddr 返回实际连接地址。配置了 server_ip 时优先用它。
func (c *Config) DialAddr() string {
	if c.ServerIP != "" {
		return net.JoinHostPort(c.ServerIP, strconv.Itoa(c.Port))
	}
	return ""
}
