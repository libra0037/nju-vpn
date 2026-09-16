package ztna

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"strconv"
	"strings"
)

// 资源表描述"哪些目标可以走隧道"。服务端只对表里命中的目标做逐流鉴权，
// 表外的包发过去也会被丢掉，所以匹配必须在客户端先做。

type resourceEntry struct {
	ipMin, ipMax uint32
	portMin      uint16
	portMax      uint16
	proto        string // tcp / udp / all
	appID        string
	groupID      string
}

type nodeAddress struct {
	group string
	addr  string
}

type resourceTable struct {
	entries []resourceEntry
	nodes   []nodeAddress
	major   string
	dns     []string
}

func ip4ToUint32(ip net.IP) (uint32, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return 0, false
	}
	return binary.BigEndian.Uint32(v4), true
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
								Protocol string `json:"protocol"`
								Port     string `json:"port"`
								Host     string `json:"host"`
							} `json:"addressList"`
						} `json:"apps"`
					} `json:"appInfo"`
					Config struct {
						NodeGroupConf struct {
							MajorNodeGroup struct {
								ID string `json:"id"`
							} `json:"majorNodeGroup"`
							NodeGroupList []struct {
								ID          string `json:"id"`
								AddressInfo []struct {
									Address string `json:"address"`
									Type    string `json:"type"`
								} `json:"addressInfo"`
							} `json:"nodeGroupList"`
						} `json:"nodeGroupConf"`
					} `json:"config"`
				} `json:"data"`
			} `json:"appList"`
			SDPPolicy struct {
				Data struct {
					ClientOption struct {
						DNSOption struct {
							FirstDNS  string `json:"firstDNS"`
							SecondDNS string `json:"secondDNS"`
						} `json:"dnsOption"`
						DNSOptionV2 struct {
							FirstDNS  string `json:"firstDNS"`
							SecondDNS string `json:"secondDNS"`
						} `json:"dnsOptionV2"`
					} `json:"clientOption"`
				} `json:"data"`
			} `json:"sdpPolicy"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, &ProtocolError{What: "资源表解析失败", Got: truncateForError(raw)}
	}

	t := &resourceTable{}
	for _, ai := range doc.Data.AppList.Data.AppInfo {
		for _, app := range ai.Apps {
			if app.AccessModel != "" && app.AccessModel != "L3VPN" {
				continue
			}
			for _, addr := range app.AddressList {
				proto := strings.ToLower(addr.Protocol)
				if proto != "tcp" && proto != "udp" && proto != "all" {
					continue
				}
				lo, hi, ok := parseIPRange(addr.Host)
				if !ok {
					continue // 域名资源走的是另一条路，这里不参与 L3 匹配
				}
				pmin, pmax := parsePortRange(addr.Port)
				t.entries = append(t.entries, resourceEntry{
					ipMin: lo, ipMax: hi, portMin: pmin, portMax: pmax,
					proto: proto, appID: app.ID, groupID: app.NodeGroupID,
				})
			}
		}
	}

	conf := doc.Data.AppList.Data.Config.NodeGroupConf
	t.major = conf.MajorNodeGroup.ID
	for _, g := range conf.NodeGroupList {
		for _, a := range g.AddressInfo {
			addr := a.Address
			if addr == "{{sdpcHost}}" {
				addr = serverHost
			}
			if !strings.Contains(addr, ":") {
				addr += ":441"
			}
			switch strings.ToLower(a.Type) {
			case "wan":
				t.nodes = append([]nodeAddress{{g.ID, addr}}, t.nodes...)
			case "lan":
				t.nodes = append(t.nodes, nodeAddress{g.ID, addr})
			}
		}
	}

	dnsOpt := doc.Data.SDPPolicy.Data.ClientOption.DNSOption
	if dnsOpt.FirstDNS == "" {
		dnsOpt = doc.Data.SDPPolicy.Data.ClientOption.DNSOptionV2
	}
	for _, s := range []string{dnsOpt.FirstDNS, dnsOpt.SecondDNS} {
		if s != "" {
			t.dns = append(t.dns, s)
		}
	}
	return t, nil
}

// parseIPRange 支持单个地址、CIDR 与 "起始-结束" 三种写法。
func parseIPRange(host string) (uint32, uint32, bool) {
	if ip := net.ParseIP(host); ip != nil {
		v, ok := ip4ToUint32(ip)
		return v, v, ok
	}
	if _, n, err := net.ParseCIDR(host); err == nil {
		lo, ok1 := ip4ToUint32(n.IP)
		mask := binary.BigEndian.Uint32(n.Mask)
		hi := lo | ^mask
		return lo, hi, ok1
	}
	if i := strings.Index(host, "-"); i > 0 {
		loIP, hiIP := net.ParseIP(host[:i]), net.ParseIP(host[i+1:])
		if loIP != nil && hiIP != nil {
			lo, ok1 := ip4ToUint32(loIP)
			hi, ok2 := ip4ToUint32(hiIP)
			return lo, hi, ok1 && ok2
		}
	}
	return 0, 0, false
}

func parsePortRange(spec string) (uint16, uint16) {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "0" {
		return 1, 65535
	}
	if i := strings.Index(spec, "-"); i > 0 {
		lo, err1 := strconv.Atoi(spec[:i])
		hi, err2 := strconv.Atoi(spec[i+1:])
		if err1 == nil && err2 == nil && lo > 0 && hi >= lo {
			return uint16(min(lo, 65535)), uint16(min(hi, 65535))
		}
		return 1, 65535
	}
	v, err := strconv.Atoi(spec)
	if err != nil || v <= 0 {
		return 1, 65535
	}
	return uint16(min(v, 65535)), uint16(min(v, 65535))
}

// match 找出目标命中的资源。只在新建一条流的时候调用一次，
// 结果随流缓存，所以这里用线性扫描就够了——条目只有几百条。
func (t *resourceTable) match(dst net.IP, proto string, port uint16) (appID, groupID string, ok bool) {
	v, ok4 := ip4ToUint32(dst)
	if !ok4 {
		return "", "", false
	}
	for _, e := range t.entries {
		if v < e.ipMin || v > e.ipMax {
			continue
		}
		if e.proto != "all" && e.proto != proto {
			continue
		}
		// ICMP 这类没有端口的协议传进来的是 0。规则里的端口段写的是 1-65535，
		// 拿 0 去比就会把整个网段的 ICMP 都判成表外——实测（2026-09-16）
		// 表现是"ping 校园网主机全丢"，而日志只说"目标不在资源表内"。
		if port != 0 && (port < e.portMin || port > e.portMax) {
			continue
		}
		return e.appID, e.groupID, true
	}
	return "", "", false
}

// candidateNodes 返回可以尝试的隧道节点，优先选给定节点组，
// 找不到就退到主节点组，再退到任意一组。
func (t *resourceTable) candidateNodes(preferred string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(group string) {
		for _, n := range t.nodes {
			if n.group != group || seen[n.addr] {
				continue
			}
			seen[n.addr] = true
			out = append(out, n.addr)
		}
	}
	add(preferred)
	add(t.major)
	for _, n := range t.nodes {
		if !seen[n.addr] {
			seen[n.addr] = true
			out = append(out, n.addr)
		}
	}
	return out
}
