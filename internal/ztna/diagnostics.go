package ztna

// RejectionCounts 是当前隧道连接的上行 Send 拒包计数；重连后从零开始。
// 有限字段不携带地址、载荷、鉴权令牌或服务端文案。
type RejectionCounts struct {
	LinkUnavailable   uint64 `json:"link_unavailable"`
	ResourceUnmatched uint64 `json:"resource_unmatched"`
	FlowRejected      uint64 `json:"flow_rejected"`
	PendingFull       uint64 `json:"pending_full"`
	FlowTableFull     uint64 `json:"flow_table_full"`
	FragmentMissing   uint64 `json:"fragment_missing"`
	FragmentOrder     uint64 `json:"fragment_order"`
	FragmentFull      uint64 `json:"fragment_full"`
	MTUExceeded       uint64 `json:"mtu_exceeded"`
	InvalidPacket     uint64 `json:"invalid_packet"`
}

// TunnelDiagnostics 只报告当前连接，不把握手或匹配成功解释成业务可达。
type TunnelDiagnostics struct {
	Connected bool            `json:"connected"`
	MTU       int             `json:"mtu"`
	Rejected  RejectionCounts `json:"rejected"`
}

// Diagnostics 读取会话拥有的连接快照，不做网络 I/O，也不推进重连。
func (s *Session) Diagnostics() TunnelDiagnostics {
	s.mu.Lock()
	conn := s.active
	closed := s.closed || s.ctx.Err() != nil
	mtu := s.l3MTU
	s.mu.Unlock()
	if conn == nil || closed {
		return TunnelDiagnostics{MTU: mtu}
	}
	conn.rejectMu.Lock()
	d := TunnelDiagnostics{MTU: conn.mtu, Rejected: conn.rejected}
	conn.rejectMu.Unlock()
	select {
	case <-conn.closeCh:
	default:
		d.Connected = true
	}
	return d
}
