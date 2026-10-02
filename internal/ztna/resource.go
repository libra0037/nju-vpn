package ztna

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/libra0037/nju-vpn/internal/dial"
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
	resources []Resource
	entries   []resourceEntry
	nodes     []nodeAddress
	major     string
	dns       []string

	// portFallbacks 是端口段看不懂、按整段（1-65535）处理的规则条数。
	// 计数而不是忽略：放宽带会让客户端多发鉴权请求，用户至少该有一条线索。
	portFallbacks int
	// badNodes 是地址不合法被丢掉的节点条数。同样计数不忽略：控制面被
	// 攻陷或证书校验被关掉时，畸形的节点地址会进 CONNECT 请求行。
	badNodes int
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
						Apps []Resource `json:"apps"`
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
	if err := validateJSON(raw); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, &ProtocolError{What: "资源表解析失败"}
	}

	t := &resourceTable{}
	apps, addresses, ips := 0, 0, 0
	for _, ai := range doc.Data.AppList.Data.AppInfo {
		for _, app := range ai.Apps {
			apps++
			addresses += len(app.AddressList)
			if apps > 4096 || addresses > 16384 || len(app.ID) > 128 || len(app.NodeGroupID) > 128 || len(app.AccessModel) > 64 {
				return nil, &ProtocolError{What: "资源数量或字段长度超过上限"}
			}
			for _, addr := range app.AddressList {
				ips += len(addr.IP)
				if len(addr.Host) > 1024 || len(addr.Protocol) > 64 || len(addr.Port) > 256 || len(addr.IP) > 64 || ips > 32768 {
					return nil, &ProtocolError{What: "资源地址字段超过上限"}
				}
				for _, ip := range addr.IP {
					if len(ip) > 64 {
						return nil, &ProtocolError{What: "资源 IP 字段过长"}
					}
				}
			}
			if app.AccessModel != "" && app.AccessModel != "L3VPN" {
				continue
			}
			t.resources = append(t.resources, app)
		}
	}
	// 匹配规则只从同一份资源事实派生；打印保留未参与 L3 匹配的地址。
	for _, app := range t.resources {
		for _, addr := range app.AddressList {
			proto := strings.ToLower(addr.Protocol)
			if proto != "tcp" && proto != "udp" && proto != "all" {
				continue
			}
			lo, hi, ok := parseIPRange(addr.Host)
			if !ok {
				continue
			}
			pmin, pmax, ok := parsePortRange(addr.Port)
			if !ok {
				t.portFallbacks++
			}
			t.entries = append(t.entries, resourceEntry{ipMin: lo, ipMax: hi, portMin: pmin, portMax: pmax, proto: proto, appID: app.ID, groupID: app.NodeGroupID})
		}
	}

	conf := doc.Data.AppList.Data.Config.NodeGroupConf
	t.major = conf.MajorNodeGroup.ID
	var wan, lan []nodeAddress
	nodeCount := 0
	if len(conf.NodeGroupList) > 256 || len(t.major) > 128 {
		return nil, &ProtocolError{What: "节点组数量或标识超过上限"}
	}
	for _, g := range conf.NodeGroupList {
		if len(g.ID) > 128 {
			return nil, &ProtocolError{What: "节点组标识过长"}
		}
		for _, a := range g.AddressInfo {
			nodeCount++
			if nodeCount > 256 || len(a.Address) > 1024 || len(a.Type) > 64 {
				return nil, &ProtocolError{What: "节点数量或字段长度超过上限"}
			}
			addr := a.Address
			if addr == "{{sdpcHost}}" {
				addr = serverHost
			}
			if !strings.Contains(addr, ":") {
				addr += ":441"
			}
			// 资源表里的地址会进探活、CONNECT 请求行与日志：控制字符、
			// 空白都能伪造出额外的行。不合法就整条丢掉并计数。
			if !dial.ValidHostPort(addr) {
				t.badNodes++
				continue
			}
			switch strings.ToLower(a.Type) {
			case "wan":
				wan = append(wan, nodeAddress{g.ID, addr})
			case "lan":
				lan = append(lan, nodeAddress{g.ID, addr})
			}
		}
	}

	slices.Reverse(wan)
	t.nodes = append(wan, lan...)
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
			return lo, hi, ok1 && ok2 && lo <= hi
		}
	}
	return 0, 0, false
}

// parsePortRange 解析规则里的端口段。第二个返回值表示"看懂了"。
//
// 看不懂时调用方按 1-65535 处理并计数：这只会多发几次鉴权请求（越权判定本来
// 就在服务端），而按"跳过这条规则"处理会让客户端把服务端放行的资源也挡掉，
// 那才是真的断网。
func parsePortRange(spec string) (uint16, uint16, bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "0" {
		return 1, 65535, true
	}
	if i := strings.Index(spec, "-"); i > 0 {
		lo, err1 := strconv.Atoi(spec[:i])
		hi, err2 := strconv.Atoi(spec[i+1:])
		if err1 == nil && err2 == nil && lo > 0 && hi >= lo && hi <= 65535 && lo <= 65535 {
			return uint16(min(lo, 65535)), uint16(min(hi, 65535)), true
		}
		return 1, 65535, false
	}
	v, err := strconv.Atoi(spec)
	if err != nil || v <= 0 || v > 65535 {
		return 1, 65535, false
	}
	return uint16(v), uint16(v), true
}

// match 找出目标命中的资源。
//
// 注意它是每条上行包都调用一次的（缓存下来的是鉴权状态，不是匹配结果），
// 所以这里只做零分配的线性扫描：条目通常几百条。条目涨到千级、上行延迟
// 可测时再谈索引——那之前做索引属于"没有测量的优化"。
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
		// ICMP 没有端口，五元组里传进来的是 0：拿它去比规则里的 1-65535 会把
		// 整个网段的 ICMP 判成表外（实测 2026-09-16：ping 校园网全丢，日志只
		// 说"目标不在资源表内"）。按协议区分，而不是按"端口是不是 0"区分——
		// TCP/UDP 里目的端口 0 是畸形包，不该因此绕过端口判断。
		if proto != "icmp" && (port < e.portMin || port > e.portMax) {
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

// Resource 是控制面发布的 L3 应用；空 AccessModel 表示服务端未标注。
// 所有可达切片在会话发布后只读，交给外部消费者时再复制。
type Resource struct {
	ID          string            `json:"id"`
	NodeGroupID string            `json:"nodeGroupId"`
	AccessModel string            `json:"accessModel"`
	AddressList []ResourceAddress `json:"addressList"`
}
type ResourceAddress struct {
	Host     string   `json:"host"`
	Protocol string   `json:"protocol"`
	Port     string   `json:"port"`
	IP       []string `json:"ip"`
}

var ErrResourceSnapshotTooLarge = errors.New("资源列表超过响应长度上限")

// 先按小字段计数，再一次编码；超限时不复制或编码整张表。可达数据只读。
func (t *resourceTable) snapshotJSON(limit int) ([]byte, error) {
	size := 2 // []
	for i, r := range t.resources {
		if i > 0 {
			size++
		}
		head := r
		head.AddressList = nil
		encoded, err := json.Marshal(head)
		if err != nil {
			return nil, err
		}
		size += len(encoded)
		if r.AddressList != nil {
			size -= 2 // null → []
			for j, a := range r.AddressList {
				if j > 0 {
					size++
				}
				encoded, err = json.Marshal(a)
				if err != nil {
					return nil, err
				}
				size += len(encoded)
				if size > limit {
					return nil, ErrResourceSnapshotTooLarge
				}
			}
		}
		if size > limit {
			return nil, ErrResourceSnapshotTooLarge
		}
	}
	if size > limit {
		return nil, ErrResourceSnapshotTooLarge
	}
	if t.resources == nil {
		return []byte("[]"), nil
	}
	return json.Marshal(t.resources)
}
