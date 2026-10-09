package ztna

import (
	"cmp"
	"encoding/json"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/libra0037/nju-vpn/internal/dial"
	"github.com/libra0037/nju-vpn/internal/domain"
)

const (
	maxResourceApps          = 4096
	maxResourceAddresses     = 16384
	maxResourceIDBytes       = 128
	maxResourceModelBytes    = 64
	maxResourceHostBytes     = 1024
	maxResourceProtocolBytes = 64
	maxResourcePortBytes     = 256
	maxResourceIPsPerAddress = 64
	maxResourceIPs           = 65536
	maxResourceIPBytes       = 64
	maxResourceGroups        = 256
	maxResourceNodes         = 256
	maxResourceNodeBytes     = 1024
	maxResourceNodeTypeBytes = 64
	maxResourceDNSBytes      = 64
)

type resourceParseStats struct {
	skippedApps, emptyAppID, unsupportedProtocol, unsupportedAddress int
	badPorts, badIPs, unsupportedIPs, missingDialIPs, badNodes       int
}

// 这棵临时树只属于解析操作；表不保留原始字段或节点排序标志。
type resourceDocument struct {
	Data struct {
		AppList struct {
			Data struct {
				AppInfo []struct {
					Apps []rawResourceApp `json:"apps"`
				} `json:"appInfo"`
				Config struct {
					NodeGroupConf struct {
						MajorNodeGroup struct {
							ID string `json:"id"`
						} `json:"majorNodeGroup"`
						NodeGroupList []struct {
							ID          string            `json:"id"`
							AddressInfo []rawResourceNode `json:"addressInfo"`
						} `json:"nodeGroupList"`
					} `json:"nodeGroupConf"`
				} `json:"config"`
			} `json:"data"`
		} `json:"appList"`
		SDPPolicy struct {
			Data struct {
				ClientOption struct {
					DNSOptionV2 struct {
						FirstDNS  string `json:"firstDNS"`
						SecondDNS string `json:"secondDNS"`
					} `json:"dnsOptionV2"`
				} `json:"clientOption"`
			} `json:"data"`
		} `json:"sdpPolicy"`
	} `json:"data"`
}

type rawResourceApp struct {
	ID          string `json:"id"`
	NodeGroupID string `json:"nodeGroupId"`
	AccessModel string `json:"accessModel"`
	AddrPretend bool   `json:"addrPretend"`
	AddressList []struct {
		Host     string   `json:"host"`
		Protocol string   `json:"protocol"`
		Port     string   `json:"port"`
		IP       []string `json:"ip"`
	} `json:"addressList"`
}

type rawResourceNode struct {
	Address string `json:"address"`
	Type    string `json:"type"`
}

func parseResourceTable(raw []byte, serverHost string) (*resourceTable, resourceParseStats, error) {
	stats := resourceParseStats{}
	fail := func(what string) (*resourceTable, resourceParseStats, error) {
		return nil, resourceParseStats{}, &ProtocolError{What: what}
	}
	if err := validateJSON(raw); err != nil {
		return nil, stats, err
	}
	var doc resourceDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fail("资源表解析失败")
	}
	t := &resourceTable{nodeGroups: make(map[string][]string)}
	apps, addresses, ips := 0, 0, 0
	for _, ai := range doc.Data.AppList.Data.AppInfo {
		for _, app := range ai.Apps {
			apps++
			addresses += len(app.AddressList)
			if apps > maxResourceApps || addresses > maxResourceAddresses || len(app.ID) > maxResourceIDBytes || len(app.NodeGroupID) > maxResourceIDBytes || len(app.AccessModel) > maxResourceModelBytes {
				return fail("资源数量或字段长度超过上限")
			}
			accepted := app.AccessModel == "L3VPN" && app.ID != ""
			if app.AccessModel != "L3VPN" {
				stats.skippedApps++
			} else if app.ID == "" {
				stats.emptyAppID++
			}
			for _, addr := range app.AddressList {
				ips += len(addr.IP)
				if len(addr.Host) > maxResourceHostBytes || len(addr.Protocol) > maxResourceProtocolBytes || len(addr.Port) > maxResourcePortBytes || len(addr.IP) > maxResourceIPsPerAddress || ips > maxResourceIPs {
					return fail("资源地址字段或下发 IP 数量超过上限")
				}
				for _, ip := range addr.IP {
					if len(ip) > maxResourceIPBytes {
						return fail("下发 IP 字段超过上限")
					}
				}
				if !accepted {
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
					stats.unsupportedProtocol++
					continue
				}
				lo, hi, ok := parsePortRange(addr.Port)
				if !ok {
					stats.badPorts++
					continue
				}
				grant, ports := resourceGrant{app.ID, app.NodeGroupID}, portRange{lo, hi}
				if prefix, ok := parseIPv4ResourceHost(addr.Host); ok {
					t.ipRules = append(t.ipRules, ipv4Rule{prefix, grant, ports, protocol})
					continue
				}
				// IPv6、CIDR 与带端口的地址不能误解成域名。
				if _, err := netip.ParseAddr(addr.Host); err == nil || strings.Contains(addr.Host, "/") || strings.Contains(addr.Host, ":") {
					stats.unsupportedAddress++
					continue
				}
				domain, ok := domain.Normalize(addr.Host, true)
				if !ok || protocol == ResourceProtocolUDP {
					stats.unsupportedAddress++
					continue
				}
				rule := tcpDomainRule{pattern: domainPattern(domain), grant: grant, ports: ports}
				if !app.AddrPretend {
					for _, value := range addr.IP {
						ip, err := netip.ParseAddr(value)
						if err != nil {
							stats.badIPs++
							continue
						}
						if !ip.Is4() {
							stats.unsupportedIPs++
							continue
						}
						if !slices.Contains(rule.dialIPs, ip) {
							rule.dialIPs = append(rule.dialIPs, ip)
						}
					}
					if len(rule.dialIPs) == 0 {
						stats.missingDialIPs++
						continue
					}
				}
				t.domainRules = append(t.domainRules, rule)
			}
		}
	}
	slices.SortStableFunc(t.ipRules, func(a, b ipv4Rule) int {
		if n := cmp.Compare(b.prefix.Bits(), a.prefix.Bits()); n != 0 {
			return n
		}
		if n := a.prefix.Addr().Compare(b.prefix.Addr()); n != 0 {
			return n
		}
		if a.protocol != b.protocol {
			if a.protocol == ResourceProtocolAll {
				return 1
			}
			if b.protocol == ResourceProtocolAll {
				return -1
			}
		}
		return 0
	})
	slices.SortStableFunc(t.domainRules, func(a, b tcpDomainRule) int {
		aStars, bStars := strings.Count(string(a.pattern), "*"), strings.Count(string(b.pattern), "*")
		if aStars == 0 && bStars != 0 {
			return -1
		}
		if bStars == 0 && aStars != 0 {
			return 1
		}
		if aStars == 0 {
			return 0
		}
		return cmp.Compare(len(b.pattern)-bStars, len(a.pattern)-aStars)
	})
	conf := doc.Data.AppList.Data.Config.NodeGroupConf
	t.majorGroup = conf.MajorNodeGroup.ID
	if len(conf.NodeGroupList) > maxResourceGroups || len(t.majorGroup) > maxResourceIDBytes {
		return fail("节点组数量或标识超过上限")
	}
	nodesByGroup := make(map[string][]rawResourceNode)
	nodeCount := 0
	for _, g := range conf.NodeGroupList {
		if len(g.ID) > maxResourceIDBytes {
			return fail("节点组标识过长")
		}
		for _, node := range g.AddressInfo {
			nodeCount++
			if nodeCount > maxResourceNodes || len(node.Address) > maxResourceNodeBytes || len(node.Type) > maxResourceNodeTypeBytes {
				return fail("节点数量或字段长度超过上限")
			}
			if node.Address == "{{sdpcHost}}" {
				node.Address = serverHost
			}
			if !strings.Contains(node.Address, ":") {
				node.Address = net.JoinHostPort(node.Address, "441")
			}
			node.Type = strings.ToLower(node.Type)
			if !dial.ValidHostPort(node.Address) || node.Type != "wan" && node.Type != "lan" {
				stats.badNodes++
				continue
			}
			host, port, _ := net.SplitHostPort(node.Address)
			if ip, err := netip.ParseAddr(host); err == nil {
				host = ip.String()
			} else {
				host = strings.ToLower(host)
			}
			p, _ := strconv.Atoi(port)
			node.Address = net.JoinHostPort(host, strconv.Itoa(p))
			nodesByGroup[g.ID] = append(nodesByGroup[g.ID], node)
		}
	}
	for group, nodes := range nodesByGroup {
		slices.SortStableFunc(nodes, func(a, b rawResourceNode) int {
			if a.Type == b.Type {
				return 0
			}
			if a.Type == "wan" {
				return -1
			}
			return 1
		})
		for _, node := range nodes {
			if !slices.Contains(t.nodeGroups[group], node.Address) {
				t.nodeGroups[group] = append(t.nodeGroups[group], node.Address)
			}
		}
	}
	dns := doc.Data.SDPPolicy.Data.ClientOption.DNSOptionV2
	for i, value := range [2]string{dns.FirstDNS, dns.SecondDNS} {
		if len(value) > maxResourceDNSBytes {
			return fail("校园 DNS 字段超过上限")
		}
		if value == "" {
			continue
		}
		ip, err := netip.ParseAddr(value)
		if err != nil || !ip.Is4() {
			return fail("校园 DNS 地址不是 IPv4")
		}
		t.dns[i] = ip
	}
	return t, stats, nil
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

// 空值与 0 是校园协议的未限制端口；非法格式不能放宽授权。
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
