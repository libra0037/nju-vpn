// Package config 负责读取服务进程的配置文件。
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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
	TLS       TLS       `yaml:"tls"`
	IPC       IPC       `yaml:"ipc"`
	MTU       int       `yaml:"mtu"`
	Log       Log       `yaml:"log"`
}

// TLS 是两条 TLS 通道的校验策略。
//
// 控制面（登录、验证码、资源表）走系统信任链：实测门户证书是公共 CA 签发的
// （DigiCert，CN=*.nju.edu.cn），校验能直接通过，口令与验证码因此不再暴露给
// 路上的中间人。数据面节点是自签证书（CN=sdp，与节点地址无关），链与名称都
// 不可能校验，只能按指纹认身份。
type TLS struct {
	// InsecureSkipVerify 关闭控制面的证书校验。默认关闭校验=false，也就是
	// 正常校验；只有网关换成系统不认的证书（自签、内网 CA）时才需要打开。
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
	// PinnedNodeSHA256 是隧道节点证书的 SHA-256 指纹（叶子证书），可写多个。
	// 分隔符（冒号、空格）与大小写都不敏感。留空时用内置的已知值，其余节点
	// 按“首次记录、之后比对”处理；一旦在这里写了指纹，就只认这些值——
	// 陌生节点会被拒绝并打印观测到的指纹，由你确认后加进来。
	PinnedNodeSHA256 []string `yaml:"pinned_node_sha256"`
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

// defaultPinnedNodeSHA256 是本部署实测过的隧道节点证书指纹。
//
// 节点用自签证书（CN=sdp，与节点地址无关），链与名称都校验不了，指纹是唯一
// 可行的判据。内置已知值的好处是第一次连接就不必依赖“首次记录”，代价是换
// 证书后要更新一次：失败信息会打印观测到的指纹与改法。
//
// 这里放了两条：同一个节点地址背后不止一台设备，两次实测拿到的是不同设备
// 的证书（自签证书的 notBefore 相差 71 秒，都是出厂模板、密钥各自生成）。
// 多写一条不会削弱校验，只是多认一台；遇到列表外的设备会按“首次记录”处理
// （配置里显式写了指纹则改为严格模式，见 TLS.PinnedNodeSHA256）。
var defaultPinnedNodeSHA256 = []string{
	"53:BE:18:61:F1:94:D0:CB:2A:96:54:70:F8:B8:7E:4D:99:9D:82:B8:7C:78:29:28:5F:60:63:B4:D1:28:53:A4",
	"21:54:05:9D:C8:84:4C:72:D8:F9:32:95:2C:D2:2E:04:9A:37:15:46:C4:E6:D1:DE:EB:5E:D1:BB:47:D1:57:54",
}

// ParseSHA256Fingerprints 把配置里的证书指纹文本解析成 32 字节。
//
// 允许 "AA:BB:…"、"AA BB …" 与不带分隔符三种写法，大小写不敏感。指纹不是
// 秘密（它随每次握手发出去），但写错一个字符就永远连不上，所以错误里带上
// 原值，让用户看得出是哪一条写坏了。
func ParseSHA256Fingerprints(list []string) ([][sha256.Size]byte, error) {
	out := make([][sha256.Size]byte, 0, len(list))
	for _, raw := range list {
		cleaned := strings.Map(func(r rune) rune {
			switch r {
			case ':', ' ', '\t', '-':
				return -1
			default:
				return r
			}
		}, raw)
		decoded, err := hex.DecodeString(cleaned)
		if err != nil || len(decoded) != sha256.Size {
			return nil, fmt.Errorf("证书指纹 %q 不是合法的 SHA-256（形如 AA:BB:…，共 32 字节）", raw)
		}
		var sum [sha256.Size]byte
		copy(sum[:], decoded)
		out = append(out, sum)
	}
	return out, nil
}

// NodePinHashes 返回该信任的节点证书指纹。
//
// 配置留空时用内置的已知值：那是本部署实测的指纹，装上就能直接连。
func (c *Config) NodePinHashes() ([][sha256.Size]byte, error) {
	list := c.TLS.PinnedNodeSHA256
	if len(list) == 0 {
		list = defaultPinnedNodeSHA256
	}
	return ParseSHA256Fingerprints(list)
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

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件 %s: %w", path, err)
	}

	var cfg Config
	// 读的还是用户给的路径（会穿透链接），记下来的必须是真实路径，
	// 否则写回落在链接上，与实例身份的口径分叉。
	cfg.sourcePath = CanonicalPath(path)
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
	// 指纹写错一个字符就永远连不上，必须在加载时就报出来，而不是等建隧道。
	if _, err := ParseSHA256Fingerprints(c.TLS.PinnedNodeSHA256); err != nil {
		return fmt.Errorf("tls.pinned_node_sha256: %w", err)
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
	// Opaque 非空或没有主机名时不可信："alice:pw@127.0.0.1:7897" 会被解析成
	// scheme=alice + opaque 主体，Redacted() 只抹 User 与口令字段，对这两种
	// 形式会原样返回含口令的字符串。
	if u.Opaque != "" || u.Host == "" {
		return "（无法安全显示的代理地址）"
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

// PersistDeviceID 把设备标识写回配置文件（顶层字段）。
func PersistDeviceID(path, id string) error {
	return persistTopLevelField(path, "device_id", id, false)
}

// persistTopLevelField 就地替换顶层字段，保留注释；没有该行时追加。
func persistTopLevelField(path, field, value string, overwrite bool) error {
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
	insertAt := -1
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			if insertAt < 0 {
				insertAt = i
			}
			continue
		}
		if len(line)-len(strings.TrimLeft(line, " 	")) != 0 {
			continue
		}
		if strings.HasPrefix(trimmed, field+":") {
			if !overwrite && existingValue(line) != "" {
				return nil
			}
			lines[i] = field + ": " + value + commentOf(line)
			return writePreservingMode(path, fi, lines)
		}
		if insertAt < 0 {
			insertAt = i + 1
		}
	}
	if insertAt < 0 {
		insertAt = len(lines)
	}
	lines = append(lines[:insertAt], append([]string{field + ": " + value}, lines[insertAt:]...)...)
	return writePreservingMode(path, fi, lines)
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
				if !isBlockMapping(trimmed, "wireguard:") {
					return fmt.Errorf("%s 的 wireguard 段不是块写法（%q）：把那一行展开成\n"+
						"wireguard:\n  private_key: ...\n再启动，或手工填好要写回的字段", path, trimmed)
				}
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

// isBlockMapping 判断一行 "key:" 是不是块映射的开头。
//
// "wireguard:" 与 "wireguard:   # 说明" 都是；"wireguard: {peer_address: ...}"
// 这种流式写法不是——往它后面插一行缩进两格的字段，整份文件就解析不过了，
// 所以那种写法必须拒绝写回（由调用方按警告处理），而不是写坏用户的配置。
func isBlockMapping(line, prefix string) bool {
	rest := strings.TrimSpace(strings.TrimPrefix(line, prefix))
	return rest == "" || strings.HasPrefix(rest, "#")
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
	// 兜底：这一层是手写的行编辑，改完必须仍然是能解析的 YAML。解析不过就
	// 放弃写回——宁可这一项没写进去（下次启动再生成），也不能把用户的配置
	// 文件写坏到下一次启动直接以“解析配置文件失败”退出。
	var probe yaml.Node
	if err := yaml.Unmarshal([]byte(content), &probe); err != nil {
		return fmt.Errorf("写回 %s 被拒绝：改动后解析不过（%w）", path, err)
	}
	// 临时名带 pid：两个进程同时写回时不会互相截断成半截 YAML。
	tmp := fmt.Sprintf("%s.tmp.%d", path, os.Getpid())
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fi.Mode().Perm())
	if err != nil {
		return fmt.Errorf("写入 %s: %w", tmp, err)
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("写入 %s: %w", tmp, err)
	}
	// 落盘之后再改名：这份文件里已经有新生成的私钥与设备标识，rename 之后
	// 才崩溃的话，用户拿到的是一个"看起来成功、内容没落盘"的配置。
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("写入 %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
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
