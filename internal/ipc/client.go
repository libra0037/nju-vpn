package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/libra0037/nju-vpn/internal/config"
)

// Client 固定创建时的配置身份；每次 Call 都在同一连接上核验后发送操作。
// 不缓存探活结果：两次调用之间监听者可能已经变化。
type Client struct {
	identity string
	endpoint string
}

// NewClient 只定位实例，不读取配置内容；空路径使用命令的默认配置路径。
func NewClient(configPath string) *Client {
	if configPath == "" {
		configPath = config.DefaultPath()
	}
	identity := ConfigIdentity(configPath)
	return &Client{identity: identity, endpoint: endpointPath(instanceTag(identity))}
}

// 零值不可用；调用失败也会关闭当前连接。
func (c *Client) Call(req Request, timeout time.Duration) (Response, error) {
	return c.CallContext(context.Background(), req, timeout)
}

// CallContext 的预算覆盖连接、身份核验和操作；取消会关闭并等待本次连接的收尾。
func (c *Client) CallContext(parent context.Context, req Request, timeout time.Duration) (response Response, resultErr error) {
	if c == nil || c.endpoint == "" || c.identity == "" {
		return Response{}, ErrEmptyEndpoint
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	conn, err := dialContext(ctx, c.endpoint)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	cancelDone := make(chan struct{})
	stopCancel := context.AfterFunc(ctx, func() {
		conn.Close()
		close(cancelDone)
	})
	defer func() {
		if !stopCancel() {
			<-cancelDone
		}
		if resultErr != nil && ctx.Err() != nil {
			resultErr = ctx.Err()
		}
	}()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return Response{}, err
	}
	reader := bufio.NewReader(conn)
	exchange := func(request Request) (Response, error) {
		if err := WriteRequest(conn, request); err != nil {
			return Response{}, fmt.Errorf("发送请求: %w", err)
		}
		response, err := ReadResponse(reader)
		if err != nil {
			return Response{}, fmt.Errorf("读取响应: %w", err)
		}
		return response, nil
	}
	identity, err := exchange(Request{Command: CmdPing})
	if err != nil {
		return Response{}, err
	}
	var reported InstanceIdentity
	if identity.Code != CodeOK || json.Unmarshal([]byte(identity.Message), &reported) != nil || reported.ConfigPath != c.identity {
		return Response{}, ErrInstanceMismatch
	}
	if req.Command == CmdPing && len(req.Args) == 0 {
		return identity, nil
	}
	return exchange(req)
}
