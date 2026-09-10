package wireguard

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"

	"njuvpn/internal/vpn"
)

// DeviceOptions 是创建 WireGuard 承载设备的参数。
type DeviceOptions struct {
	// MTU 会通过 Relay 报告给 WireGuard。
	MTU int
	// Endpoint 是校园网隧道端点。
	Endpoint *vpn.TunnelEndpoint
	// Mapper 在 peer 地址与校园网分配地址之间改写 IP 包。
	Mapper *Mapper
	// PrivateKey 是本端的 WireGuard 私钥。
	PrivateKey Key
	// ListenPort 是监听的 UDP 端口。
	ListenPort int
	// ListenHost 决定绑定在回环还是全部网卡。零值是回环。
	ListenHost ListenHost
	// PeerPublicKey 是唯一允许接入的客户端公钥；为零值时设备照常监听，
	// 但没有任何客户端能接入。
	PeerPublicKey Key
	// PeerAddress 是分配给客户端的地址。
	PeerAddress net.IP
	// Verbose 打开 wireguard-go 的详细日志。
	Verbose bool
	// Bind 覆盖默认的 UDP 绑定，供测试注入。
	Bind conn.Bind
}

// Device 是 WireGuard 承载层。
//
// 客户端通过 UDP 接入，本进程把解出来的 IP 包交给校园网隧道，
// 反向则把隧道收到的包加密送回客户端。这里不创建 TUN 网卡：
// 承载端是内存里的 Relay，客户端自带用户态网络栈。
type Device struct {
	dev *device.Device

	closeOnce sync.Once
}

// NewDevice 创建并启动承载设备。
func NewDevice(opts DeviceOptions) (*Device, error) {
	if opts.PrivateKey.IsZero() {
		return nil, fmt.Errorf("缺少 WireGuard 私钥")
	}
	if opts.Endpoint == nil {
		return nil, fmt.Errorf("缺少隧道端点")
	}
	// 端口 0 表示交给系统分配，测试与临时部署用得到。
	if opts.ListenPort < 0 || opts.ListenPort > 65535 {
		return nil, fmt.Errorf("监听端口超出范围: %d", opts.ListenPort)
	}

	relay := NewRelay(RelayOptions{
		MTU:      opts.MTU,
		Endpoint: opts.Endpoint,
		Mapper:   opts.Mapper,
	})

	bind := opts.Bind
	if bind == nil {
		bind = newBind(opts.ListenHost)
	}
	level := device.LogLevelError
	if opts.Verbose {
		level = device.LogLevelVerbose
	}
	dev := device.NewDevice(relay, bind, device.NewLogger(level, "wireguard: "))

	conf, err := uapiConfig(opts)
	if err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.IpcSet(conf); err != nil {
		dev.Close()
		return nil, fmt.Errorf("应用 WireGuard 配置: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("启动 WireGuard 设备: %w", err)
	}

	return &Device{dev: dev}, nil
}

// uapiConfig 组装 wireguard-go 的 UAPI 配置文本。
//
// 密钥在 UAPI 里是十六进制，不是配置文件里的 base64——写错了
// 设备会直接报 invalid key。
func uapiConfig(opts DeviceOptions) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(opts.PrivateKey[:]))
	fmt.Fprintf(&b, "listen_port=%d\n", opts.ListenPort)

	if opts.PeerPublicKey.IsZero() {
		return b.String(), nil
	}

	v4 := opts.PeerAddress.To4()
	if opts.PeerAddress != nil && v4 == nil {
		return "", fmt.Errorf("peer 地址必须是 IPv4: %v", opts.PeerAddress)
	}

	// replace_peers 先清空，保证配置是幂等的：设备上只会存在这一个 peer。
	b.WriteString("replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(opts.PeerPublicKey[:]))
	if v4 != nil {
		// allowed_ip 决定哪些目的地址的包会被送进这条隧道。
		fmt.Fprintf(&b, "allowed_ip=%s/32\n", v4.String())
	}
	return b.String(), nil
}

// SetPeer 在不重启设备的前提下替换 peer。
//
// 重新生成客户端密钥时不必重建隧道：隧道登录与 WireGuard 设备是两件
// 独立的事，后者可以就地更新。这一点很实用——重建隧道要重新登录一次。
func (d *Device) SetPeer(pub Key, addr net.IP) error {
	if pub.IsZero() {
		return fmt.Errorf("peer 公钥为空")
	}
	if addr == nil || addr.To4() == nil {
		return fmt.Errorf("peer 地址必须是 IPv4: %v", addr)
	}
	conf := "replace_peers=true\n" +
		"public_key=" + hex.EncodeToString(pub[:]) + "\n" +
		"allowed_ip=" + addr.To4().String() + "/32\n"
	if err := d.dev.IpcSet(conf); err != nil {
		return fmt.Errorf("更新 peer: %w", err)
	}
	return nil
}

// uapiConfig 是一次 IpcGet 的解析结果。
//
// 以前 ListenPort 与 Stats 各自把整份 UAPI 配置序列化并解析一遍，
// 而且 Stats 用指向切片元素的指针，靠"同一 peer 的字段总在下一个 append
// 之前写完"才成立——按索引写就没有这种隐式前提了。
type deviceConfig struct {
	listenPort int
	peers      []PeerStats
}

// parseUAPI 解析 UAPI 的 key=value 文本。
func parseUAPI(out string) deviceConfig {
	var cfg deviceConfig
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "listen_port":
			cfg.listenPort, _ = strconv.Atoi(strings.TrimSpace(value))
		case "public_key":
			cfg.peers = append(cfg.peers, PeerStats{PublicKey: value})
		case "rx_bytes":
			if i := len(cfg.peers) - 1; i >= 0 {
				cfg.peers[i].RxBytes, _ = strconv.ParseInt(value, 10, 64)
			}
		case "tx_bytes":
			if i := len(cfg.peers) - 1; i >= 0 {
				cfg.peers[i].TxBytes, _ = strconv.ParseInt(value, 10, 64)
			}
		case "last_handshake_time_sec":
			if i := len(cfg.peers) - 1; i >= 0 {
				if sec, _ := strconv.ParseInt(value, 10, 64); sec > 0 {
					cfg.peers[i].LastHandshake = time.Unix(sec, 0)
				}
			}
		}
	}
	return cfg
}

// ListenPort 返回设备实际监听的 UDP 端口。
//
// 配置里写 0 时由系统分配，只有回读才知道真实端口，测试依赖这一点。
func (d *Device) ListenPort() (int, error) {
	cfg, err := d.config()
	if err != nil {
		return 0, err
	}
	if cfg.listenPort == 0 {
		return 0, fmt.Errorf("读取不到 listen_port")
	}
	return cfg.listenPort, nil
}

// PeerStats 是某个 peer 的流量统计。
type PeerStats struct {
	// PublicKey 是 peer 的公钥（base64）。
	PublicKey string
	// RxBytes / TxBytes 是设备视角的收发字节数。
	RxBytes int64
	TxBytes int64
	// LastHandshake 是最近一次握手的时间，零值表示从未握手。
	LastHandshake time.Time
}

// Stats 返回所有 peer 的流量统计。
//
// 这是"隧道到底通没通"最直接的判据：Clash 一旦握手成功，
// 这里就会有非零的收发与握手时间。
func (d *Device) Stats() ([]PeerStats, error) {
	cfg, err := d.config()
	if err != nil {
		return nil, err
	}
	return cfg.peers, nil
}

// config 读一次 UAPI 配置并解析。
func (d *Device) config() (deviceConfig, error) {
	out, err := d.dev.IpcGet()
	if err != nil {
		return deviceConfig{}, err
	}
	return parseUAPI(out), nil
}

// Close 停止设备。可安全重复调用。
func (d *Device) Close() error {
	d.closeOnce.Do(func() {
		// device.Close 会顺带关闭 tun（也就是 Relay），不用再关一次。
		d.dev.Close()
	})
	return nil
}
