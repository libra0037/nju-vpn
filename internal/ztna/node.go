package ztna

import (
	"context"
	"crypto/tls"
	"sync"
	"time"

	"github.com/libra0037/nju-vpn/internal/dial"
)

const maxConcurrentProbes = 8

type probeResult struct {
	addr string
	conn *tls.Conn
	err  error
}

func (r probeResult) close() {
	if r.conn != nil {
		// 不发送节点 TLS 的 close_notify，直接释放未接纳连接的底层 I/O。
		_ = r.conn.NetConn().Close()
	}
}

// fn 返回已完成 TLS 与配置指纹校验的连接。选中的连接转移给调用者；
// 其余连接均关闭，并等待全部工作者。结果只缓存一项，限制尚未接纳的连接。
func probeNodes(ctx context.Context, fn func(context.Context, string) (*tls.Conn, error), addrs []string, timeout time.Duration) (string, *tls.Conn, error) {
	if len(addrs) == 0 {
		return "", nil, &ProtocolError{What: "资源表里没有可用的隧道节点"}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	jobs := make(chan string, len(addrs))
	for _, addr := range addrs {
		jobs <- addr
	}
	close(jobs)
	results := make(chan probeResult, 1)
	var wg sync.WaitGroup
	for range min(maxConcurrentProbes, len(addrs)) {
		wg.Go(func() {
			for addr := range jobs {
				if ctx.Err() != nil {
					return
				}
				conn, err := fn(ctx, addr)
				r := probeResult{addr: addr, conn: conn, err: err}
				if ctx.Err() != nil {
					r.close()
					return
				}
				select {
				case results <- r:
					// 结果接收者负责连接；发送后工作者不再访问它。
				case <-ctx.Done():
					r.close()
					return
				}
			}
		})
	}
	defer func() {
		cancel()
		wg.Wait()
		for len(results) > 0 {
			r := <-results
			r.close()
		}
	}()
	var last error
	for range addrs {
		select {
		case r := <-results:
			if err := ctx.Err(); err != nil {
				r.close()
				return "", nil, dial.Wrap("探测隧道节点", err)
			}
			if r.err == nil {
				return r.addr, r.conn, nil
			}
			r.close()
			last = r.err
		case <-ctx.Done():
			return "", nil, dial.Wrap("探测隧道节点", ctx.Err())
		}
	}
	return "", nil, dial.Wrap("探测隧道节点", last)
}
