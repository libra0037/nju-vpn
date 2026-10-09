package ipc

import (
	"encoding/json"
	"errors"
	"net/netip"

	"github.com/libra0037/nju-vpn/internal/domain"
)

var ErrResourceSnapshotTooLarge = errors.New("资源列表超过响应长度上限")

// Resources 是当前 IPC 资源响应的唯一格式；不承载校园鉴权身份。
type Resources struct {
	IP         []IPResource        `json:"ip"`
	TCPDomains []TCPDomainResource `json:"tcpDomains"`
	DNS        ResourceDNS         `json:"dns"`
}
type IPResource struct {
	Prefix   netip.Prefix `json:"prefix"`
	Protocol string       `json:"protocol"`
	Ports    [2]uint16    `json:"ports"`
}
type TCPDomainResource struct {
	Pattern string    `json:"pattern"`
	Ports   [2]uint16 `json:"ports"`
}
type ResourceDNS struct {
	Primary   string `json:"primary"`
	Secondary string `json:"secondary"`
}

// EncodeResources 的预算包含 JSON 转义，超限整单失败。
func EncodeResources(resources Resources, limit int) ([]byte, error) {
	body, err := json.Marshal(resources)
	if err != nil {
		return nil, err
	}
	if len(body) > limit {
		return nil, ErrResourceSnapshotTooLarge
	}
	return body, nil
}

// Validate 在任何字段输出前检查完整响应。
func (r Resources) Validate() error {
	invalid := errors.New("资源快照响应格式非法")
	if r.IP == nil || r.TCPDomains == nil {
		return invalid
	}
	portsOK := func(p [2]uint16) bool { return p[0] > 0 && p[0] <= p[1] }
	for _, ip := range r.IP {
		if !ip.Prefix.IsValid() || !ip.Prefix.Addr().Is4() || ip.Prefix != ip.Prefix.Masked() || !portsOK(ip.Ports) {
			return invalid
		}
		switch ip.Protocol {
		case "tcp", "udp", "all":
		default:
			return invalid
		}
	}
	for _, rule := range r.TCPDomains {
		name, ok := domain.Normalize(rule.Pattern, true)
		if !ok || name != rule.Pattern || !portsOK(rule.Ports) {
			return invalid
		}
	}
	for _, value := range [2]string{r.DNS.Primary, r.DNS.Secondary} {
		if value == "" {
			continue
		}
		ip, err := netip.ParseAddr(value)
		if err != nil || !ip.Is4() || ip.String() != value {
			return invalid
		}
	}
	return nil
}
