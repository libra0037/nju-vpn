package ztna

import (
	"context"
	"fmt"
	"time"

	"github.com/libra0037/nju-vpn/internal/dial"
)

// 节点选择：所有候选地址并行探一次 TCP，取最快连上的那个。
// 串行探测在第一个地址不可达时要白等一个超时，而节点列表里经常有
// 明确连不通的地址（例如只有内网才通的 lan 地址）。

type probeResult struct {
	addr string
	dur  time.Duration
	err  error
}

func probeNodes(ctx context.Context, dialFn dial.DialFunc, addrs []string, timeout time.Duration) (string, error) {
	if len(addrs) == 0 {
		return "", &ProtocolError{What: "资源表里没有可用的隧道节点"}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ch := make(chan probeResult, len(addrs))
	for _, addr := range addrs {
		go func(addr string) {
			start := time.Now()
			conn, err := dialWithContext(ctx, dialFn, "tcp", addr)
			if err != nil {
				ch <- probeResult{addr: addr, err: err}
				return
			}
			_ = conn.Close()
			ch <- probeResult{addr: addr, dur: time.Since(start)}
		}(addr)
	}

	var lastErr error
	for range addrs {
		select {
		case r := <-ch:
			if r.err == nil {
				return r.addr, nil
			}
			lastErr = r.err
		case <-ctx.Done():
			if lastErr != nil {
				return "", fmt.Errorf("隧道节点均不可达（最后一个错误: %w）", lastErr)
			}
			return "", fmt.Errorf("探测隧道节点超时: %w", ctx.Err())
		}
	}
	return "", fmt.Errorf("隧道节点均不可达: %w", lastErr)
}
