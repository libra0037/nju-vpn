package ztna

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/libra0037/nju-vpn/internal/domain"
)

// ResourceProtocol 使用 IP 协议号；-1 表示资源允许所有已支持的协议。
type ResourceProtocol int16

const (
	ResourceProtocolAll ResourceProtocol = -1
	ResourceProtocolTCP ResourceProtocol = protoTCP
	ResourceProtocolUDP ResourceProtocol = protoUDP
)

func (p ResourceProtocol) String() string {
	switch p {
	case ResourceProtocolAll:
		return "all"
	case ResourceProtocolTCP:
		return "tcp"
	case ResourceProtocolUDP:
		return "udp"
	default:
		return "unknown"
	}
}

// 发布后所有可达数据只读。零值为空表，不能授权任何目标。
// IP 规则同时供 L3 与 L4 使用；域名的下发 IP 只是建连候选。
type resourceTable struct {
	ipRules     []ipv4Rule
	domainRules []tcpDomainRule
	dns         [2]netip.Addr
	nodeGroups  map[string][]string
	majorGroup  string
}

type resourceGrant struct {
	appID       string
	nodeGroupID string
}

type portRange struct{ first, last uint16 }

type ipv4Rule struct {
	prefix   netip.Prefix
	grant    resourceGrant
	ports    portRange
	protocol ResourceProtocol
}

type domainPattern string

type tcpDomainRule struct {
	pattern domainPattern
	grant   resourceGrant
	ports   portRange
	// 空切片表示按实际请求域名建连；非空表示用这些下发 IPv4。
	dialIPs []netip.Addr
}

// TCPTarget 由 NewTCPTarget 构造，保存实际 IPv4 或 ASCII 域名及非零端口。
// 零值无效；通配符只属于资源模式，不是连接目标。
type TCPTarget struct {
	host string
	port uint16
}

func NewTCPTarget(host string, port uint16) (TCPTarget, error) {
	if port == 0 {
		return TCPTarget{}, &ProtocolError{What: "TCP 目标端口为零"}
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if !ip.Is4() {
			return TCPTarget{}, ErrTCPAddressUnsupported
		}
		return TCPTarget{ip.String(), port}, nil
	}
	domain, ok := domain.Normalize(host, false)
	if !ok {
		return TCPTarget{}, &ProtocolError{What: "TCP 目标域名非法"}
	}
	return TCPTarget{domain, port}, nil
}

type tcpRoute struct {
	grant   resourceGrant
	target  TCPTarget
	dialIPs []netip.Addr
}

// 完整匹配后才返回；端口不符须继续扫描，ICMP 没有端口。
func (t *resourceTable) matchIP(dst netip.Addr, proto uint8, port uint16) (resourceGrant, bool) {
	for _, rule := range t.ipRules {
		if !rule.prefix.Contains(dst) || rule.protocol != ResourceProtocolAll && rule.protocol != ResourceProtocol(proto) {
			continue
		}
		if proto != protoICMP && (port < rule.ports.first || port > rule.ports.last) {
			continue
		}
		return rule.grant, true
	}
	return resourceGrant{}, false
}

func (t *resourceTable) matchTCP(target TCPTarget) (tcpRoute, bool) {
	if ip := targetIPv4(target.host); ip.IsValid() {
		grant, ok := t.matchIP(ip, protoTCP, target.port)
		return tcpRoute{grant: grant, target: target}, ok
	}
	for _, rule := range t.domainRules {
		if target.port < rule.ports.first || target.port > rule.ports.last || !rule.pattern.matches(target.host) {
			continue
		}
		return tcpRoute{rule.grant, target, rule.dialIPs}, true
	}
	return tcpRoute{}, false
}

// ParseAddr 为非 IP 域名分配错误对象；基准确认每次多一次堆分配。
// 在构造边界已规范输入的前提下，这里只识别规范 IPv4 文本，其余仍是域名。
func targetIPv4(host string) netip.Addr {
	var octets [4]byte
	part, start, value := 0, 0, 0
	for i := 0; i <= len(host); i++ {
		if i == len(host) || host[i] == '.' {
			if part >= 4 || i == start || i-start > 3 || i-start > 1 && host[start] == '0' {
				return netip.Addr{}
			}
			octets[part] = byte(value)
			part++
			start = i + 1
			value = 0
			continue
		}
		if host[i] < '0' || host[i] > '9' {
			return netip.Addr{}
		}
		value = value*10 + int(host[i]-'0')
		if value > 255 {
			return netip.Addr{}
		}
	}
	if part != 4 {
		return netip.Addr{}
	}
	return netip.AddrFrom4(octets)
}

// * 可跨点，整个域名锚定。只前进查找文字段，不回溯、不分配。
func (p domainPattern) matches(host string) bool {
	pattern := string(p)
	prefix, tail, wildcard := strings.Cut(pattern, "*")
	if !wildcard {
		return pattern == host
	}
	if !strings.HasPrefix(host, prefix) {
		return false
	}
	host = host[len(prefix):]
	for {
		segment, next, more := strings.Cut(tail, "*")
		if !more {
			return strings.HasSuffix(host, segment)
		}
		pos := strings.Index(host, segment)
		if pos < 0 {
			return false
		}
		host = host[pos+len(segment):]
		tail = next
	}
}

// 候选列表转移给拨号任务；不返回表内切片。组内在解析时已按 WAN 优先排序。
func (t *resourceTable) candidateNodes(preferred string) []string {
	var out []string
	seen := make(map[string]bool)
	add := func(group string) {
		for _, addr := range t.nodeGroups[group] {
			if !seen[addr] {
				seen[addr] = true
				out = append(out, addr)
			}
		}
	}
	add(preferred)
	add(t.majorGroup)
	groups := make([]string, 0, len(t.nodeGroups))
	for group := range t.nodeGroups {
		groups = append(groups, group)
	}
	slices.Sort(groups)
	for _, group := range groups {
		add(group)
	}
	return out
}
