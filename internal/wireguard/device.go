package wireguard

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/device"

	"github.com/libra0037/nju-vpn/internal/l3"
)

// DeviceOptions 是创建 WireGuard 承载设备的参数。
//
// 这里只有"进程活着就不变"的东西：私钥、监听端口、MTU。会话相关的
// （隧道端点、地址改写）与接入方公钥都通过 SetSession / SetPeer 在运行
// 期挂上去，因为设备比任何一次校园网会话都活得久。
type DeviceOptions struct {
	// MTU 会通过 Relay 报告给 WireGuard。
	MTU int
	// PrivateKey 是本端的 WireGuard 私钥。
	PrivateKey Key
	// ListenPort 是监听的 UDP 端口。
	ListenPort int
	// ListenHost 决定绑定在回环还是全部网卡。零值是回环。
	ListenHost ListenHost
	// Verbose 打开 wireguard-go 的详细日志。
	Verbose bool
}

// Device 是 WireGuard 承载层。
//
// 客户端通过 UDP 接入，本进程把解出来的 IP 包交给校园网隧道，
// 反向则把隧道收到的包加密送回客户端。这里不创建 TUN 网卡：
// 承载端是内存里的 Relay，客户端自带用户态网络栈。
//
// 设备与校园网会话是两条独立的生命周期：设备在服务进程启动时就建好
// （端口冲突、私钥写错这类问题当场暴露），会话则随 njuvpn start / stop
// 反复挂上与摘掉。
type Device struct {
	dev *device.Device
	// relay 是同一个对象的另一种视角：会话换绑要经过它。
	relay *Relay

	listenPort int
	listenHost ListenHost

	closeOnce sync.Once
}

// NewDevice 创建并启动承载设备。
func NewDevice(opts DeviceOptions) (*Device, error) {
	if opts.PrivateKey.IsZero() {
		return nil, fmt.Errorf("缺少 WireGuard 私钥")
	}
	// 端口 0 表示交给系统分配，测试与临时部署用得到。
	if opts.ListenPort < 0 || opts.ListenPort > 65535 {
		return nil, fmt.Errorf("监听端口超出范围: %d", opts.ListenPort)
	}

	relay := NewRelay(RelayOptions{MTU: opts.MTU})

	bind := newBind(opts.ListenHost)
	level := device.LogLevelError
	if opts.Verbose {
		level = device.LogLevelVerbose
	}
	dev := device.NewDevice(relay, bind, device.NewLogger(level, "wireguard: "))

	if err := dev.IpcSet(uapiConfig(opts.PrivateKey, opts.ListenPort)); err != nil {
		dev.Close()
		return nil, fmt.Errorf("应用 WireGuard 配置: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("启动 WireGuard 设备: %w", err)
	}

	return &Device{
		dev:        dev,
		relay:      relay,
		listenPort: opts.ListenPort,
		listenHost: opts.ListenHost,
	}, nil
}

// uapiConfig 组装设备级配置：私钥与监听端口。
//
// 密钥在 UAPI 里是十六进制，不是配置文件里的 base64——写错了
// 设备会直接报 invalid key。
func uapiConfig(privateKey Key, listenPort int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(privateKey[:]))
	fmt.Fprintf(&b, "listen_port=%d\n", listenPort)
	return b.String()
}

// peerConfig 组装接入方的配置文本。
//
// replace_peers 先清空，保证配置是幂等的：设备上只会存在这一个 peer；
// allowed_ip 决定哪些目的地址的包会被送进这条隧道。
func peerConfig(pub Key, addr net.IP) (string, error) {
	if addr == nil || addr.To4() == nil {
		return "", fmt.Errorf("peer 地址必须是 IPv4: %v", addr)
	}
	return "replace_peers=true\n" +
		"public_key=" + hex.EncodeToString(pub[:]) + "\n" +
		"allowed_ip=" + addr.To4().String() + "/32\n", nil
}

// SetSession 把承载层接到一次校园网会话上。
func (d *Device) SetSession(ep *l3.Endpoint, mapper *Mapper) {
	d.relay.InstallSession(ep, mapper)
}

// ClearSession 摘掉当前会话：设备继续监听，但不再有任何包进出隧道。
func (d *Device) ClearSession() {
	d.relay.ClearSession()
}

// SetPeer 在不重启设备的前提下替换 peer。
//
// 重新生成客户端密钥时不必重建隧道：隧道登录与 WireGuard 设备是两件
// 独立的事，后者可以就地更新。这一点很实用——重建隧道要重新登录一次。
func (d *Device) SetPeer(pub Key, addr net.IP) error {
	if pub.IsZero() {
		return fmt.Errorf("peer 公钥为空")
	}
	conf, err := peerConfig(pub, addr)
	if err != nil {
		return err
	}
	if err := d.dev.IpcSet(conf); err != nil {
		return fmt.Errorf("更新 peer: %w", err)
	}
	// 换了 key 就等于重新开始：客户端得重新握手，下行方向才再次放行。
	d.relay.HoldDownlink(true)
	return nil
}

// ClearPeer 摘掉接入方。
//
// 隧道断开后必须做这件事：设备还在监听，若 peer 留着，客户端会握手成功，
// 然后每个包都撞上"没有会话"被丢掉——从客户端看是"连上了但什么都打不开"，
// 比干脆连不上难查得多。
func (d *Device) ClearPeer() error {
	if err := d.dev.IpcSet("replace_peers=true\n"); err != nil {
		return fmt.Errorf("摘除 peer: %w", err)
	}
	// 设备里没有 peer 了：交给 WireGuard 的包会因为找不到目的 peer 被静默
	// 丢弃，这里不必再扣。
	d.relay.HoldDownlink(false)
	return nil
}

// deviceConfig 是一次 IpcGet 的解析结果。
//
// 只解析真正用得到的字段：设备配置由本进程写下去，回读只为确认系统分配的
// 端口。
type deviceConfig struct {
	listenPort int
}

// parseUAPI 解析 UAPI 的 key=value 文本。
func parseUAPI(out string) deviceConfig {
	var cfg deviceConfig
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if key == "listen_port" {
			cfg.listenPort, _ = strconv.Atoi(strings.TrimSpace(value))
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

// config 读一次 UAPI 配置并解析。
func (d *Device) config() (deviceConfig, error) {
	out, err := d.dev.IpcGet()
	if err != nil {
		return deviceConfig{}, err
	}
	return parseUAPI(out), nil
}

// ListenPortOrDefault 返回设备实际监听的 UDP 端口。
//
// 端口配成 0 时由系统分配，只有回读才知道真实端口；回读失败时退到配置值，
// 只为日志好看一点，不承担正确性。
func (d *Device) ListenPortOrDefault() int {
	if actual, err := d.ListenPort(); err == nil && actual > 0 {
		return actual
	}
	return d.listenPort
}

// ListenHost 返回设备绑定的范围。
func (d *Device) ListenHost() ListenHost { return d.listenHost }

// Close 停止设备。可安全重复调用。
func (d *Device) Close() error {
	d.closeOnce.Do(func() {
		// device.Close 会顺带关闭 tun（也就是 Relay），不用再关一次。
		d.dev.Close()
	})
	return nil
}
