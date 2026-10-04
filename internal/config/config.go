// Package config 负责读取服务进程的配置文件。
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"net"
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
	ServerIP string `yaml:"server_ip"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	// LoginDomain 是口令登录的域。服务端通常给出多个可选域，
	// 留空时用返回的第一个口令方式。
	LoginDomain string `yaml:"login_domain"`
	// DeviceID 是本机在服务端那边的设备标识。它决定"授信终端"绑的是谁，
	// 首次启动自动生成并写回配置文件——换了它就要重新做一次短信认证。
	DeviceID  string    `yaml:"device_id"`
	Proxy     string    `yaml:"proxy"`
	WireGuard WireGuard `yaml:"wireguard"`
	// PinnedNodeSPKISHA256 是自签节点唯一的信任来源，程序只读、不自动补录。
	// 每项为 DER SubjectPublicKeyInfo 的 SHA-256 摘要，使用标准 Base64。
	PinnedNodeSPKISHA256 []string `yaml:"pinned_node_spki_sha256"`
	MTU                  int      `yaml:"mtu"`
	Log                  Log      `yaml:"log"`
}

type WireGuard struct {
	ListenPort int `yaml:"listen_port"`
	// ListenHost 是 loopback（默认）或 all。
	ListenHost    string `yaml:"listen_host"`
	PrivateKey    string `yaml:"private_key"`
	PeerPublicKey string `yaml:"peer_public_key"`
	PeerAddress   string `yaml:"peer_address"`
}

type Log struct {
	Level string `yaml:"level"`
}

// 两层隧道交接同一个内层 IP 包，不能在这里再扣 WireGuard 外层开销。
const (
	MinMTU         = 576
	maxNodePins    = 16
	maxConfigBytes = 256 * 1024
)

// NodeSPKIPins 在配置边界验证指纹并交出独立的不可变值副本。
func (c *Config) NodeSPKIPins() ([][sha256.Size]byte, error) {
	list := c.PinnedNodeSPKISHA256
	if len(list) == 0 || len(list) > maxNodePins {
		return nil, fmt.Errorf("pinned_node_spki_sha256 必须包含 1-%d 项", maxNodePins)
	}
	out := make([][sha256.Size]byte, 0, len(list))
	seen := make(map[[sha256.Size]byte]bool, len(list))
	for i, raw := range list {
		decoded, err := base64.StdEncoding.Strict().DecodeString(raw)
		if err != nil || len(decoded) != sha256.Size || base64.StdEncoding.EncodeToString(decoded) != raw {
			return nil, fmt.Errorf("pinned_node_spki_sha256 第 %d 项须为 32 字节摘要的标准 Base64", i+1)
		}
		var sum [sha256.Size]byte
		copy(sum[:], decoded)
		if seen[sum] {
			return nil, fmt.Errorf("pinned_node_spki_sha256 第 %d 项重复", i+1)
		}
		seen[sum] = true
		out = append(out, sum)
	}
	return out, nil
}

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
// 配置里有校园网口令、设备标识与 WireGuard 私钥，0644 会让它们顺手进备份、
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

// LoadForClient 只读完整配置，供登录命令使用；管理命令仅凭路径定位实例。
func LoadForClient(path string) (*Config, error) {
	return load(path)
}

// CanonicalPath 把用户给的配置路径规范成真实路径：先绝对化，再解开符号链接。
//
// 规范形式是实例身份（IPC 端点、日志名）与写回目标的共同口径。写回是
// “写临时文件 + rename”，rename 替换的是目录项本身：路径不解析链接时，
// 用户配置的那条链接会被换成一份新的普通文件，他真正在编辑的文件永远
// 收不到生成的内容，而实例身份却按真实路径算——两边就此分叉。
//
// 解析失败（例如文件还不存在）时退回绝对路径：端点必须能算出来。
func CanonicalPath(path string) string {
	p := path
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	if real, err := filepath.EvalSymlinks(p); err == nil {
		p = real
	}
	return p
}

func load(path string) (*Config, error) {
	if path == "" {
		path = DefaultPath()
	}

	path = CanonicalPath(path)
	data, err := readConfig(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件 %s: %w", path, err)
	}

	return parseConfig(data, path)
}

func parseConfig(data []byte, path string) (*Config, error) {
	if _, err := configDocument(data); err != nil {
		return nil, err
	}
	var cfg Config
	// 读的还是用户给的路径（会穿透链接），记下来的必须是真实路径，
	// 否则写回落在链接上，与实例身份的口径分叉。
	cfg.sourcePath = path
	// KnownFields 让键名写错时直接报错，而不是静默回落默认值。
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件失败：检查键名和字段类型")
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
		// 1400 是已实测可用的默认值，不是服务端的已知上限。
		c.MTU = 1400
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
			return errors.New("server_ip 不是合法地址")
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
	// IPv4 总长度与校园数据帧的包长均为 16 位；1400 只是默认值。
	if c.MTU < MinMTU || c.MTU > math.MaxUint16 {
		return fmt.Errorf("mtu 超出范围（应在 %d-%d 之间）", MinMTU, math.MaxUint16)
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
		return errors.New("log.level 只能是 info 或 debug")
	}
	if err := validateListenHost(c.WireGuard.ListenHost); err != nil {
		return err
	}
	// 指纹写错一个字符就永远连不上，必须在加载时就报出来，而不是等建隧道。
	if _, err := c.NodeSPKIPins(); err != nil {
		return err
	}
	if ip := net.ParseIP(c.WireGuard.PeerAddress); ip == nil || ip.To4() == nil {
		return errors.New("wireguard.peer_address 必须是 IPv4 地址")
	}
	return nil
}

// Warnings 返回不影响启动、但用户应该知道的问题。
func (c *Config) Warnings() []string {
	var out []string
	if c.permNote != "" {
		out = append(out, c.permNote)
	}
	if c.WireGuard.PeerPublicKey == "" {
		out = append(out, "未配置 wireguard.peer_public_key，任何对端都无法接入")
	}
	if c.LoginDomain == "" {
		out = append(out, "未配置 login_domain，将使用服务端返回的第一个口令登录方式")
	}
	if c.DeviceID == "" {
		out = append(out, "未配置 device_id，启动时会自动生成并写回配置文件")
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
	case "", "loopback", "all":
		return nil
	default:
		return errors.New("wireguard.listen_host 只能是 loopback 或 all")
	}
}

// validateHost 检查目标主机名。写成 "host:port" 是最常见的错误：
// 端口是独立字段，拼起来会变成 "[host:port]:443"。
func validateHost(field, host string) error {
	if net.ParseIP(host) != nil {
		return nil
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return fmt.Errorf("%s 里带了端口（端口请写在 port 字段）", field)
	}
	for _, r := range host {
		if r <= ' ' || r == '/' || r == '\\' {
			return fmt.Errorf("%s 含非法字符", field)
		}
	}
	if strings.ContainsAny(host, "[]%@") {
		return fmt.Errorf("%s 含非法字符（方括号、百分号或 @）", field)
	}
	return nil
}

// ServerAddr 返回 "host:port" 形式的目标地址。
func (c *Config) ServerAddr() string {
	return net.JoinHostPort(c.Server, strconv.Itoa(c.Port))
}

// DialAddr 返回实际连接地址。配置了 server_ip 时优先用它。
//
// 它是给拨号用的：本机解析不了学校域名时（校园网内经常如此），业务上仍然
// 用 server 生成 Host 头与 SNI，只有 TCP 连到 server_ip。
func (c *Config) DialAddr() string {
	if c.ServerIP != "" {
		return net.JoinHostPort(c.ServerIP, strconv.Itoa(c.Port))
	}
	return ""
}

// ConnectAddr 返回需要实际建连的地址：优先 server_ip，否则用 server。
func (c *Config) ConnectAddr() string {
	if addr := c.DialAddr(); addr != "" {
		return addr
	}
	return c.ServerAddr()
}
