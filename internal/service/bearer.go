package service

import (
	"fmt"
	"log"
	"net"

	"github.com/libra0037/nju-vpn/internal/config"
	"github.com/libra0037/nju-vpn/internal/wireguard"
	"github.com/libra0037/nju-vpn/internal/ztna"
)

// bearer 是 WireGuard 承载层在服务进程里的那份状态。
//
// 它活到进程结束，而校园网会话只是它上面的一次挂载：设备在进程启动时就
// 建起来，因此"端口被占""私钥写错""peer 地址非法"这类配置问题全部在启动
// 时暴露，不会等到用户输完验证码、占掉服务端一条短信之后才报出来。
type bearer struct {
	dev      *wireguard.Device
	peerKey  wireguard.Key
	peerAddr net.IP

	// installedKey / installedAddr 记录设备上现在装的是哪一对。两者都没变
	// 时 applyPeer 什么都不做：上游对 replace_peers 的语义是“清掉全部 peer
	// 再装”，重建会作废客户端已经握好的会话密钥（它拿旧密钥发的包我们解不开，
	// 要等它自己的密钥对到期才重新握手），表现是隧道 up 却长时间不通。
	installedKey  wireguard.Key
	installedAddr net.IP
}

func newBearer(cfg *config.Config) (*bearer, error) {
	privateKey, err := wireguard.ParseKey(cfg.WireGuard.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("wireguard.private_key: %w", err)
	}
	var peerKey wireguard.Key
	if cfg.WireGuard.PeerPublicKey != "" {
		if peerKey, err = wireguard.ParseKey(cfg.WireGuard.PeerPublicKey); err != nil {
			return nil, fmt.Errorf("wireguard.peer_public_key: %w", err)
		}
		// 全零公钥能通过 base64 解析，却不是合法的 x25519 公钥点。
		// 不拦住的话它会一路走到设备配置，客户端表现为永远握手失败。
		if peerKey.IsZero() {
			return nil, fmt.Errorf("wireguard.peer_public_key 是全零公钥，不是合法的 WireGuard 公钥")
		}
	}
	// 只承载 IPv4：地址映射与 allowed_ip 都按 /32 写。
	peerAddr := net.ParseIP(cfg.WireGuard.PeerAddress)
	if peerAddr == nil || peerAddr.To4() == nil {
		return nil, fmt.Errorf("wireguard.peer_address 必须是 IPv4 地址: %q", cfg.WireGuard.PeerAddress)
	}

	dev, err := wireguard.NewDevice(wireguard.DeviceOptions{
		MTU:        cfg.MTU,
		PrivateKey: privateKey,
		ListenPort: cfg.WireGuard.ListenPort,
		ListenHost: listenHost(cfg.WireGuard.ListenHost),
		Verbose:    cfg.Log.Level == "debug",
	})
	if err != nil {
		return nil, fmt.Errorf("启动 WireGuard 承载: %w", err)
	}
	return &bearer{dev: dev, peerKey: peerKey, peerAddr: peerAddr}, nil
}

// attach 把一次校园网会话接到承载上。
//
// 地址映射依赖这次登录分配到的校园网地址，所以两张表总是一起换：
// 换到一半（上行已指向新会话、下行还按旧地址改写）会让每个包都被丢掉。
func (b *bearer) attach(sess *ztna.Session) error {
	vip := sess.ClientIP()
	if vip == nil {
		return fmt.Errorf("服务端没有分配校园网地址，无法建立地址映射")
	}
	// 隧道地址可能在会话中途变（服务端下发地址列表）：映射按端点上的当前
	// 值现取，换了地址之后上下行自动跟着走，不必重建会话或重装 peer。
	mapper, err := wireguard.NewDynamicMapper(b.peerAddr, sess.Endpoint().LocalAddr4)
	if err != nil {
		return fmt.Errorf("地址映射: %w", err)
	}
	b.dev.SetSession(sess.Endpoint(), mapper)
	return b.applyPeer()
}

// detach 摘掉当前会话。
//
// 先摘 peer 再摘会话：设备还在监听，留着 peer 会让客户端握手成功，而它的
// 包其实已经没有隧道可走——从客户端看是"连上了但什么都打不开"。
func (b *bearer) detach() {
	if err := b.dev.ClearPeer(); err != nil {
		log.Printf("摘除 WireGuard peer 时出错: %v", err)
	}
	b.installedKey = wireguard.Key{}
	b.installedAddr = nil
	b.dev.ClearSession()
}

// applyPeer 把接入方公钥装到设备上。
//
// 没配置 peer 公钥时什么都不做：设备照常监听，只是没人能接入。
func (b *bearer) applyPeer() error {
	if b.peerKey.IsZero() {
		return nil
	}
	// 默认按“公钥不变”处理：设备上已经是这一对就一个字节都不下发，客户端
	// 那边的密钥对、端点与下行闸门都原样保留。
	if !b.installedKey.IsZero() && b.installedKey == b.peerKey && b.installedAddr.Equal(b.peerAddr) {
		return nil
	}
	if err := b.dev.SetPeer(b.peerKey, b.peerAddr); err != nil {
		return fmt.Errorf("配置接入公钥: %w", err)
	}
	b.installedKey = b.peerKey
	b.installedAddr = append(net.IP(nil), b.peerAddr...)
	return nil
}

// summary 描述承载层的监听状态，供启动日志用。
//
// 端口以设备实际绑定的为准：配置里的 0 表示让系统分配。
func (b *bearer) summary() string {
	port := b.dev.ListenPortOrDefault()
	scope := "仅本机（127.0.0.1）"
	if b.dev.ListenHost() == wireguard.ListenAll {
		scope = "全部网卡"
	}
	if b.peerKey.IsZero() {
		return fmt.Sprintf("UDP %d（%s）已就绪；未配置 wireguard.peer_public_key，任何客户端都无法接入", port, scope)
	}
	return fmt.Sprintf("UDP %d（%s）已就绪，peer 地址 %s", port, scope, b.peerAddr)
}

// close 停止设备。可安全重复调用。
func (b *bearer) close() { b.dev.Close() }

// listenHost 解析配置里的监听范围，非法值在配置校验阶段已经拦下。
func listenHost(s string) wireguard.ListenHost {
	host, err := wireguard.ParseListenHost(s)
	if err != nil {
		return wireguard.ListenLoopback
	}
	return host
}
