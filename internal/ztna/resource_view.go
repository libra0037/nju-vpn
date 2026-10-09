package ztna

import (
	"errors"
	"net/netip"
)

var ErrResourcesUnavailable = errors.New("当前没有已登录会话的资源快照")

// ResourceView 是一次查询的独占副本，不含授权身份、节点或建连候选。
type ResourceView struct {
	IP         []IPResourceView
	TCPDomains []TCPDomainView
	DNS        [2]netip.Addr
}

type IPResourceView struct {
	Prefix   netip.Prefix
	Protocol ResourceProtocol
	Ports    [2]uint16
}

type TCPDomainView struct {
	Pattern string
	Ports   [2]uint16
}

func (t *resourceTable) view() ResourceView {
	out := ResourceView{IP: make([]IPResourceView, len(t.ipRules)), TCPDomains: make([]TCPDomainView, len(t.domainRules)), DNS: t.dns}
	for i, rule := range t.ipRules {
		out.IP[i] = IPResourceView{rule.prefix, rule.protocol, [2]uint16{rule.ports.first, rule.ports.last}}
	}
	for i, rule := range t.domainRules {
		out.TCPDomains[i] = TCPDomainView{string(rule.pattern), [2]uint16{rule.ports.first, rule.ports.last}}
	}
	return out
}

// Resources 不依赖 L3 就绪，不做 I/O；发布与关闭在会话锁内判断。
func (s *Session) Resources() (ResourceView, error) {
	s.mu.Lock()
	if s.closed || s.ctx.Err() != nil || s.table == nil {
		s.mu.Unlock()
		return ResourceView{}, ErrResourcesUnavailable
	}
	table := s.table
	s.mu.Unlock()
	return table.view(), nil
}
