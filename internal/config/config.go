// Package config 负责读取服务进程的配置文件。
package config

import (
	"bytes"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config 是服务进程的全部可配置项。
type Config struct {
	// sourcePath 是这份配置的来源文件，用于把生成的内容写回原文件。
	sourcePath string
	// permNote 记录加载时对文件权限做了什么，由 Warnings 报给用户。
	permNote string

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
	ListenPort int `yaml:"listen_port"`
	// ListenHost 是 loopback（默认）或 all。
	ListenHost    string `yaml:"listen_host"`
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

// SetSourcePath 记录配置来源，供按配置构造 Config 的调用方（与服务测试）使用。
func (c *Config) SetSourcePath(path string) { c.sourcePath = path }

// DefaultPath 返回当前平台的默认配置文件路径。
//
// 两个平台都放在用户自己的目录下：服务进程以普通用户运行，系统目录
// （/etc、ProgramData）既写不进去，也要求不该有的特权。
func DefaultPath() string {
	home, _ := os.UserHomeDir()
	return defaultPath(runtime.GOOS, os.Getenv, home)
}

// defaultPath 与运行时环境解耦，让两个分支都进单测。
//
// 上一次改动把 Windows 分支的反斜杠全丢了，njuvpn 还被吃成 juvpn，
// 而 Linux CI 永远编译不到那一行——参数化就是为了不再发生这种事。
func defaultPath(goos string, getenv func(string) string, home string) string {
	if goos == "windows" {
		if dir := getenv("LOCALAPPDATA"); dir != "" {
			return dir + `\njuvpn\config.yaml`
		}
		if home != "" {
			return home + `\AppData\Local\njuvpn\config.yaml`
		}
		return `njuvpn\config.yaml`
	}
	if dir := getenv("XDG_CONFIG_HOME"); dir != "" {
		return dir + "/njuvpn/config.yaml"
	}
	if home != "" {
		return home + "/.config/njuvpn/config.yaml"
	}
	return "/etc/njuvpn/config.yaml"
}

// Load 读取配置文件，供服务进程与探测命令使用。
//
// 不因为权限拒绝加载（属主可能是别人），但会把过宽的文件权限收紧到 0600：
// 这是个人机器上的单用户工具，权限不构成隔离边界，凭据也不该默认摊开。
func Load(path string) (*Config, error) {
	cfg, err := load(path)
	if err != nil {
		return nil, err
	}
	cfg.permNote = restrictPermissions(cfg.SourcePath())
	return cfg, nil
}

// restrictPermissions 把配置文件的权限收紧到 0600，返回要提示用户的话。
//
// 配置里有校园网口令、TOTP 密钥与 WireGuard 私钥，0644 会让它们顺手进备份、
// 进打包给别人排查的压缩包、进镜像快照。这不是隔离边界（挡不住 root，
// 也挡不住同账户的进程），只是别让它默认摊开。
//
// 收紧失败不阻塞启动：文件属主可能是别人（例如 root 建的配置），
// 能读到就够了。
func restrictPermissions(path string) string {
	if runtime.GOOS == "windows" || path == "" {
		// Windows 的权限模型是 ACL，另一套动作；那里的默认位置
		//（%LOCALAPPDATA%）本来就只对本人可见。
		return ""
	}
	fi, err := os.Stat(path)
	if err != nil {
		return ""
	}
	perm := fi.Mode().Perm()
	if perm&0o077 == 0 {
		return ""
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Sprintf("配置文件 %s 的权限是 %04o（同机其他用户可读），且无法收紧: %v", path, perm, err)
	}
	return fmt.Sprintf("配置文件 %s 的权限是 %04o，已收紧为 0600", path, perm)
}

// LoadForClient 读取命令行客户端需要的部分（只有 IPC 端点）。
//
// 与 Load 的区别是它不动文件权限：CLI 只是要算 IPC 端点，没必要——
// 也不该——替服务进程去 chmod 配置文件。
//
// 读不出来时返回 nil 加错误，由调用方决定怎么回退（CLI 的回落是"按默认
// 路径派生端点"，因为端点只依赖路径，不依赖内容）。以前这里回一个空配置，
// 而调用方自己另造回退值，那个返回值没有任何消费者。
func LoadForClient(path string) (*Config, error) {
	return load(path)
}

func load(path string) (*Config, error) {
	if path == "" {
		path = DefaultPath()
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
	// password 允许留空：此时由 `njuvpn start` 在终端现问，经本地套接字
	// 交给服务进程，只留在内存里（不落盘、不进 argv、不进日志）。
	if c.MTU < MinMTU || c.MTU > MaxMTU {
		return fmt.Errorf("mtu 超出范围: %d（应在 %d-%d 之间，1320 适合默认隧道）", c.MTU, MinMTU, MaxMTU)
	}
	// 0 在 applyDefaults 里已经被换成默认端口，这里不会见到。
	if p := c.WireGuard.ListenPort; p < 1 || p > 65535 {
		return fmt.Errorf("wireguard.listen_port 超出范围: %d", p)
	}
	// 取值不校验的话，写错（例如 warn）会静默按 info 跑，
	// 而用户以为拿到了更详细的日志。
	switch c.Log.Level {
	case "info", "debug":
	default:
		return fmt.Errorf("log.level 只能是 info 或 debug，收到 %q", c.Log.Level)
	}
	if err := validateListenHost(c.WireGuard.ListenHost); err != nil {
		return err
	}
	if ip := net.ParseIP(c.WireGuard.PeerAddress); ip == nil || ip.To4() == nil {
		return fmt.Errorf("wireguard.peer_address 必须是 IPv4 地址: %q", c.WireGuard.PeerAddress)
	}
	if c.IPC.Endpoint != "" {
		if err := validateEndpoint(c.IPC.Endpoint); err != nil {
			return err
		}
	}
	return nil
}

// validateEndpoint 检查显式配置的 IPC 端点。
//
// 相对路径会随工作目录漂移：同一个实例从不同目录发起命令会被算成另一个
// 端点，进而把一个跑着的实例当成"没在运行"，再拉起一个——两个进程抢同
// 一个账号。留空表示按配置文件的路径派生，不需要写。
func validateEndpoint(endpoint string) error {
	if runtime.GOOS == "windows" {
		if !strings.HasPrefix(endpoint, pipePrefixForConfig) {
			return fmt.Errorf("ipc.endpoint 在 Windows 下必须是命名管道（以 %s 开头）: %q", pipePrefixForConfig, endpoint)
		}
		return nil
	}
	if !filepath.IsAbs(endpoint) {
		return fmt.Errorf("ipc.endpoint 必须是绝对路径: %q", endpoint)
	}
	return nil
}

// pipePrefixForConfig 与 ipc 包里的管道前缀保持一致。
//
// 这里不引用 ipc 包：config 是叶子，被 ipc 之外的许多包依赖，反过来依赖
// 会把依赖图绕成一团。取值只有这一个，重复一份的代价小于绕圈。
const pipePrefixForConfig = `\\.\pipe\`

// RedactProxy 把代理地址里的口令抹掉，供日志与状态输出使用。
//
// 代理地址支持 user:pass@host 写法，原文不该落到任何日志里（排查时经常
// 整份贴出去）。解析不出来时也不回显原文：它可能就是一段带凭据的地址。
func RedactProxy(proxy string) string {
	if proxy == "" {
		return ""
	}
	u, err := url.Parse(proxy)
	if err != nil {
		return "（无法解析的代理地址）"
	}
	return u.Redacted()
}

// Warnings 返回不影响启动、但用户应该知道的问题。
func (c *Config) Warnings() []string {
	var out []string
	if c.permNote != "" {
		out = append(out, c.permNote)
	}
	if c.WireGuard.PeerPublicKey == "" {
		out = append(out, "未配置 wireguard.peer_public_key，任何客户端都无法接入")
	}
	if c.TOTPSecret == "" {
		out = append(out, "未配置 totp_secret，二次验证时需要人工输入验证码")
	}
	if c.Password == "" {
		out = append(out, "未配置 password，njuvpn start 会提示输入（只留在服务进程内存里）")
	}
	return out
}

// validateListenHost 校验监听范围。
//
// 这里不引用 wireguard 包：那会让 config → wireguard → vpn 形成依赖，
// 而 vpn 的测试又要读配置。取值集合必须与 wireguard.ParseListenHost 一致。
func validateListenHost(s string) error {
	switch s {
	case "", "loopback", "local", "127.0.0.1", "all", "any", "0.0.0.0":
		return nil
	default:
		return fmt.Errorf("wireguard.listen_host 只能是 loopback 或 all，收到 %q", s)
	}
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
	if strings.ContainsAny(host, "[]%@") {
		return fmt.Errorf("%s 含非法字符（方括号、百分号或 @）: %q", field, host)
	}
	return nil
}

// PersistPrivateKey 把自动生成的 WireGuard 私钥写回配置文件。
//
// 已经有了就不覆盖：两个进程同时首启同一份配置时，后写的那个会让盘上的
// 私钥与正在跑的那个进程内存里的不一致——之后所有客户端配置都会失效。
func PersistPrivateKey(path, key string) error {
	return persistWireGuardField(path, "private_key", key, false)
}

// PersistPeerPublicKey 把客户端公钥写回配置文件。
//
// 这一条是用户显式发起的操作，要覆盖旧值。
func PersistPeerPublicKey(path, key string) error {
	return persistWireGuardField(path, "peer_public_key", key, true)
}

// persistWireGuardField 就地替换 wireguard 段里的某个字段，保留原有注释——
// 用 YAML 序列化整份配置会把注释全部丢掉，而那份文件是给人看的。
// 找不到对应行时按情况插入或追加一段。
//
// overwrite 为 false 时，字段已经有非空值就原样保留（私钥自举用得上：
// 两个进程同时首启同一份配置时，先写的那把才算数）。
func persistWireGuardField(path, field, value string, overwrite bool) error {
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
		if strings.HasPrefix(trimmed, field+":") {
			if !overwrite && existingValue(line) != "" {
				return nil
			}
			// 保留行尾注释：样例文件里 private_key 那行就带着说明，
			// 写回私钥时丢掉它等于破坏用户手写的配置。
			lines[i] = line[:indent] + field + ": " + value + commentOf(line)
			return writePreservingMode(path, fi, lines)
		}
	}

	switch {
	case sectionAt >= 0:
		// 有 wireguard 段但没有 private_key 行，插到段尾。
		insertAt := sectionEnd + 1
		lines = append(lines[:insertAt], append([]string{"  " + field + ": " + value}, lines[insertAt:]...)...)
	default:
		// 完全没有 wireguard 段，追加一段。
		lines = append(lines, "wireguard:", "  "+field+": "+value)
	}
	return writePreservingMode(path, fi, lines)
}

// commentOf 取出行尾注释（连前面的分隔空格），没有注释就返回空串。
// existingValue 取出某一行里字段的当前值（去掉行尾注释与引号）。
func existingValue(line string) string {
	i := strings.Index(line, ":")
	if i < 0 {
		return ""
	}
	rest := line[i+1:]
	if j := strings.Index(rest, "#"); j >= 0 {
		rest = rest[:j]
	}
	return strings.Trim(strings.TrimSpace(rest), "\"'")
}

// 只用于我们自己改写的那一行：值里不可能出现 #（是 base64 或十六进制）。
func commentOf(line string) string {
	i := strings.Index(line, "#")
	if i < 0 {
		return ""
	}
	return " " + strings.TrimSpace(line[i:])
}

// writePreservingMode 写回文件并保持原有权限。
func writePreservingMode(path string, fi os.FileInfo, lines []string) error {
	content := strings.Join(lines, "\n")
	// 临时名带 pid：两个进程同时写回时不会互相截断成半截 YAML。
	tmp := fmt.Sprintf("%s.tmp.%d", path, os.Getpid())
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
