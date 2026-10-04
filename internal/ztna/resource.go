package ztna

import (
	"cmp"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/libra0037/nju-vpn/internal/dial"
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

// IPv4Resource 是归一化的 L3 规则：Host 为网络前缀，Port 为闭区间。
type IPv4Resource struct {
	ID          string           `json:"id"`
	NodeGroupID string           `json:"nodeGroupId"`
	Protocol    ResourceProtocol `json:"protocol"`
	Host        netip.Prefix     `json:"host"`
	Port        [2]uint16        `json:"port"`
}

type ResourceDNS struct {
	FirstDNS  string `json:"firstDNS"`
	SecondDNS string `json:"secondDNS"`
}

type ResourceNode struct {
	Address string `json:"address"`
	Type    string `json:"type"` // wan / lan
}

// L3Resources 同时供逐包匹配与 IPC 打印使用。会话发布后所有可达数据只读。
// DNS 仅用于展示配置提示，不参与报文解析或改写。
type L3Resources struct {
	IP        []IPv4Resource            `json:"ip"`
	DNS       ResourceDNS               `json:"dns"`
	NodeGroup map[string][]ResourceNode `json:"nodegroup"`
}

type resourceTable struct {
	L3Resources
	major    string
	badPorts int
	badNodes int
}

func parseResourceTable(raw []byte, serverHost string) (*resourceTable, error) {
	var doc struct {
		Data struct {
			AppList struct {
				Data struct {
					AppInfo []struct {
						Apps []struct {
							ID          string `json:"id"`
							NodeGroupID string `json:"nodeGroupId"`
							AccessModel string `json:"accessModel"`
							AddressList []struct {
								Host     string `json:"host"`
								Protocol string `json:"protocol"`
								Port     string `json:"port"`
							} `json:"addressList"`
						} `json:"apps"`
					} `json:"appInfo"`
					Config struct {
						NodeGroupConf struct {
							MajorNodeGroup struct {
								ID string `json:"id"`
							} `json:"majorNodeGroup"`
							NodeGroupList []struct {
								ID          string         `json:"id"`
								AddressInfo []ResourceNode `json:"addressInfo"`
							} `json:"nodeGroupList"`
						} `json:"nodeGroupConf"`
					} `json:"config"`
				} `json:"data"`
			} `json:"appList"`
			SDPPolicy struct {
				Data struct {
					ClientOption struct {
						DNSOptionV2 ResourceDNS `json:"dnsOptionV2"`
					} `json:"clientOption"`
				} `json:"data"`
			} `json:"sdpPolicy"`
		} `json:"data"`
	}
	if err := validateJSON(raw); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, &ProtocolError{What: "资源表解析失败"}
	}

	t := &resourceTable{L3Resources: L3Resources{
		IP: []IPv4Resource{}, NodeGroup: make(map[string][]ResourceNode),
	}}
	apps, addresses := 0, 0
	for _, ai := range doc.Data.AppList.Data.AppInfo {
		for _, app := range ai.Apps {
			apps++
			addresses += len(app.AddressList)
			if apps > 4096 || addresses > 16384 || len(app.ID) > 128 || len(app.NodeGroupID) > 128 || len(app.AccessModel) > 64 {
				return nil, &ProtocolError{What: "资源数量或字段长度超过上限"}
			}
			for _, addr := range app.AddressList {
				if len(addr.Host) > 1024 || len(addr.Protocol) > 64 || len(addr.Port) > 256 {
					return nil, &ProtocolError{What: "资源地址字段超过上限"}
				}
				if app.AccessModel != "L3VPN" {
					continue
				}
				host, ok := parseIPv4ResourceHost(addr.Host)
				if !ok {
					continue
				}
				var protocol ResourceProtocol
				switch strings.ToLower(addr.Protocol) {
				case "tcp":
					protocol = ResourceProtocolTCP
				case "udp":
					protocol = ResourceProtocolUDP
				case "all":
					protocol = ResourceProtocolAll
				default:
					continue
				}
				lo, hi, ok := parsePortRange(addr.Port)
				if !ok {
					t.badPorts++
					continue
				}
				t.IP = append(t.IP, IPv4Resource{ID: app.ID, NodeGroupID: app.NodeGroupID,
					Protocol: protocol, Host: host, Port: [2]uint16{lo, hi}})
			}
		}
	}
	// 前缀长度决定优先级；协议与端口未匹配时仍继续扫描。
	// 同键保留控制面的顺序，不猜测应用身份的额外优先级。
	slices.SortStableFunc(t.IP, func(a, b IPv4Resource) int {
		if n := cmp.Compare(b.Host.Bits(), a.Host.Bits()); n != 0 {
			return n
		}
		if n := a.Host.Addr().Compare(b.Host.Addr()); n != 0 {
			return n
		}
		if a.Protocol != b.Protocol {
			if a.Protocol == ResourceProtocolAll {
				return 1
			}
			if b.Protocol == ResourceProtocolAll {
				return -1
			}
		}
		return 0
	})

	conf := doc.Data.AppList.Data.Config.NodeGroupConf
	t.major = conf.MajorNodeGroup.ID
	if len(conf.NodeGroupList) > 256 || len(t.major) > 128 {
		return nil, &ProtocolError{What: "节点组数量或标识超过上限"}
	}
	nodeCount := 0
	for _, g := range conf.NodeGroupList {
		if len(g.ID) > 128 {
			return nil, &ProtocolError{What: "节点组标识过长"}
		}
		for _, node := range g.AddressInfo {
			nodeCount++
			if nodeCount > 256 || len(node.Address) > 1024 || len(node.Type) > 64 {
				return nil, &ProtocolError{What: "节点数量或字段长度超过上限"}
			}
			if node.Address == "{{sdpcHost}}" {
				node.Address = serverHost
			}
			if !strings.Contains(node.Address, ":") {
				node.Address += ":441"
			}
			node.Type = strings.ToLower(node.Type)
			// 地址会进入探活与 CONNECT 请求行；拒绝控制字符、空白和非法端口。
			if !dial.ValidHostPort(node.Address) || node.Type != "wan" && node.Type != "lan" {
				t.badNodes++
				continue
			}
			t.NodeGroup[g.ID] = append(t.NodeGroup[g.ID], node)
		}
	}
	for _, nodes := range t.NodeGroup {
		slices.SortStableFunc(nodes, func(a, b ResourceNode) int {
			if a.Type == b.Type {
				return 0
			}
			if a.Type == "wan" {
				return -1
			}
			return 1
		})
	}

	t.DNS = doc.Data.SDPPolicy.Data.ClientOption.DNSOptionV2
	for _, field := range []*string{&t.DNS.FirstDNS, &t.DNS.SecondDNS} {
		if *field == "" {
			continue
		}
		addr, err := netip.ParseAddr(*field)
		if err != nil || !addr.Is4() {
			return nil, &ProtocolError{What: "校园 DNS 地址不是 IPv4"}
		}
		*field = addr.String()
	}
	return t, nil
}

func parseIPv4ResourceHost(host string) (netip.Prefix, bool) {
	if addr, err := netip.ParseAddr(host); err == nil && addr.Is4() {
		return netip.PrefixFrom(addr, 32), true
	}
	prefix, err := netip.ParsePrefix(host)
	if err != nil || !prefix.Addr().Is4() {
		return netip.Prefix{}, false
	}
	return prefix.Masked(), true
}

// 空值与 0 表示未限制端口；其他格式必须是有效单端口或闭区间，非法值不放宽。
func parsePortRange(spec string) (uint16, uint16, bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "0" {
		return 1, 65535, true
	}
	loText, hiText, rangeSpec := strings.Cut(spec, "-")
	lo, err := strconv.ParseUint(loText, 10, 16)
	if err != nil || lo == 0 {
		return 0, 0, false
	}
	hi := lo
	if rangeSpec {
		hi, err = strconv.ParseUint(hiText, 10, 16)
		if err != nil || hi < lo {
			return 0, 0, false
		}
	}
	return uint16(lo), uint16(hi), true
}

// match 在排序后的规则中寻找第一个完整匹配；逐包扫描保持零分配。
func (t *resourceTable) match(dst netip.Addr, proto uint8, port uint16) (appID, groupID string, ok bool) {
	for _, rule := range t.IP {
		if !rule.Host.Contains(dst) || rule.Protocol != ResourceProtocolAll && rule.Protocol != ResourceProtocol(proto) {
			continue
		}
		// ICMP 无端口；TCP/UDP 的端口 0 不得绕过资源端口限制。
		if proto != protoICMP && (port < rule.Port[0] || port > rule.Port[1]) {
			continue
		}
		return rule.ID, rule.NodeGroupID, true
	}
	return "", "", false
}

// candidateNodes 优先给定组，再主节点组，再按组 ID 排序的其余组；组内 WAN 优先。
func (t *resourceTable) candidateNodes(preferred string) []string {
	var out []string
	seen := make(map[string]bool)
	add := func(group string) {
		for _, node := range t.NodeGroup[group] {
			if !seen[node.Address] {
				seen[node.Address] = true
				out = append(out, node.Address)
			}
		}
	}
	add(preferred)
	add(t.major)
	groups := make([]string, 0, len(t.NodeGroup))
	for group := range t.NodeGroup {
		groups = append(groups, group)
	}
	slices.Sort(groups)
	for _, group := range groups {
		add(group)
	}
	return out
}

var ErrResourceSnapshotTooLarge = errors.New("资源列表超过响应长度上限")

// 编码同一份只读状态；输入有数量与字段预算，服务进程串行编码资源响应。
// 超出调用方预算时整单拒绝，不返回部分 JSON。
func (t *resourceTable) snapshotJSON(limit int) ([]byte, error) {
	body, err := json.Marshal(t.L3Resources)
	if err != nil {
		return nil, err
	}
	if len(body) > limit {
		return nil, ErrResourceSnapshotTooLarge
	}
	return body, nil
}
