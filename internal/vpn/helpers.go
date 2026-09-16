package vpn

import (
	"context"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

// deadlineFrom 返回一个不超过 ctx 截止时间的 deadline。
//
// 隧道和 portal 的每一步都要有超时：uTLS 明确要求握手前设好 deadline，
// 否则对端"收下连接不回包"就能让 Read 永久阻塞。
func deadlineFrom(ctx context.Context, d time.Duration) time.Time {
	deadline := time.Now().Add(d)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		return ctxDeadline
	}
	return deadline
}

// watchCancel 让 ctx 取消时立刻关掉连接，返回注销函数。
//
// 只设 deadline 不够：deadline 是"最坏情况下的上限"，而用户敲 Ctrl-C 或
// stop 时希望的是马上返回。挂上之后，阻塞在读写上的调用会立刻带着错误
// 醒过来，不必干等满 Handshake 那 20 秒。
//
// 连接交出去之后就不能再挂了：数据阶段有各自的关闭机制（Run 里的
// AfterFunc、会话的 closeLocal），这里多挂一份只会在正常路径上
// 提前把还能用的连接关掉。所以调用方必须在返回前注销。
func watchCancel(ctx context.Context, conn net.Conn) func() {
	if ctx.Done() == nil {
		return func() {}
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	return func() { stop() }
}

// tagContains 判断标签的取值里是否包含某个子串。
func tagContains(body []byte, tag, sub string) bool {
	v, ok := tagValue(body, tag)
	return ok && strings.Contains(v, sub)
}

// sessionIDSource 是能提供 TLS ServerHello SessionId 的连接。
//
// 生产实现包住 uTLS 连接；测试注入的连接自己实现它，
// 这样协议层不需要真的握手就能被完整覆盖。
type sessionIDSource interface {
	ServerHelloSessionID() ([]byte, error)
}

// utlsPortalConn 是 portal 方向的 uTLS 连接。
type utlsPortalConn struct {
	*utls.UConn
}

// ServerHelloSessionID 返回 ServerHello 里的 SessionId。
//
// 旧实现直接解引用 conn.HandshakeState.ServerHello，握手没走完时
// 这里是 nil——一次空指针 panic 就能带走整个服务进程。
func (c *utlsPortalConn) ServerHelloSessionID() ([]byte, error) {
	if c.UConn == nil || c.HandshakeState.ServerHello == nil {
		return nil, &ProtocolError{Step: "portal-token", Reason: "TLS 握手未完成，拿不到 ServerHello"}
	}
	return c.HandshakeState.ServerHello.SessionId, nil
}

// serverSessionID 取出连接上的 SessionId。
func serverSessionID(conn net.Conn) ([]byte, error) {
	src, ok := conn.(sessionIDSource)
	if !ok {
		return nil, &ProtocolError{Step: "portal-token", Reason: "连接类型无法提供 ServerHello SessionId"}
	}
	return src.ServerHelloSessionID()
}
