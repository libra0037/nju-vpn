package vpn

import "fmt"

// 服务端控制码。首个 4 字节小端整数，出现在 36 字节的控制回复里。
// 码表来自公开的协议实现（见 HANDOFF.md 的参考实现一节）。
const (
	ControlSendIP      = 0  // 成功，后跟分配到的 IP
	ControlRxAck       = 1  // 下行流握手回执
	ControlTxAck       = 2  // 上行流握手回执
	ControlServerReset = 3  // 服务端重置了会话
	ControlRecovered   = 4  // 会话已恢复
	ControlIPBusy      = 5  // 地址被占用
	ControlShutdown    = 8  // 服务端要求断开：会话不存在，或登录与建隧道不是同一源 IP
	ControlIPConflict  = 9  // 地址冲突
	ControlIPKick      = 14 // 被踢下线
	ControlHeartbeat   = 15 // 心跳
)

// controlName 返回控制码的可读名称。
func controlName(code byte) string {
	switch code {
	case ControlSendIP:
		return "SendIP"
	case ControlRxAck:
		return "RxAck"
	case ControlTxAck:
		return "TxAck"
	case ControlServerReset:
		return "ServerReset"
	case ControlRecovered:
		return "Recovered"
	case ControlIPBusy:
		return "IpBusy"
	case ControlShutdown:
		return "Shutdown"
	case ControlIPConflict:
		return "IpConflict"
	case ControlIPKick:
		return "IpKick"
	case ControlHeartbeat:
		return "Heartbeat"
	default:
		return fmt.Sprintf("Unknown(%d)", code)
	}
}

// controlMessage 给出控制码对应的可操作提示。
func controlMessage(code byte) string {
	switch code {
	case ControlServerReset:
		return "服务端重置了会话（ServerReset）。常见原因：该账号已有一条隧道会话未释放，或短时间内建立次数过多"
	case ControlIPBusy:
		return "分配的地址正被占用（IpBusy）"
	case ControlShutdown:
		return "服务端要求断开（Shutdown）。常见原因：会话不存在（TWFID 已失效），或登录与建隧道来自不同的源 IP"
	case ControlIPConflict:
		return "地址冲突（IpConflict）"
	case ControlIPKick:
		return "被服务端踢下线（IpKick）"
	default:
		return "服务端拒绝：" + controlName(code)
	}
}

// ControlError 表示服务端用控制码拒绝了请求。
type ControlError struct {
	Code    byte
	Context string
}

func (e *ControlError) Error() string {
	if e.Context != "" {
		return fmt.Sprintf("%s：%s", e.Context, controlMessage(e.Code))
	}
	return controlMessage(e.Code)
}

// Retryable 判断该控制码是否值得重试。
//
// 3(ServerReset) 与 5(IpBusy) 是暂时性的；
// 8(Shutdown)、9(IpConflict)、14(IpKick) 是终止性的，重试只会继续被拒。
func (e *ControlError) Retryable() bool {
	return e.Code == ControlServerReset || e.Code == ControlIPBusy
}
