# njuvpn

NJU VPN 的重新实现。协议层从旧仓库 `NJUConnect`（只读参考，不再改动）迁移而来。

目标形态：**一个二进制，三个角色**。

```
njuvpn run                        服务进程，由 systemd / Windows SCM 拉起
njuvpn start|stop|status|auth     命令行客户端，通过 IPC 与服务进程通信
njuvpn service install|uninstall  安装 / 卸载操作系统服务
```

## 目录结构

```
cmd/njuvpn/            子命令分发，只做参数解析和输出格式化
internal/vpn/          协议层：登录 + uTLS 隧道（从旧仓库复制）
internal/wireguard/    TunRelay：tun.Device 实现，把 WireGuard 和隧道对接
internal/ipc/          IPC 传输层，Linux unix socket / Windows 命名管道
internal/service/      服务进程主体：状态机 + 隧道生命周期
internal/config/       配置读取与校验
```

## 从旧仓库迁移了什么

| 新文件 | 来源 | 改动 |
|---|---|---|
| `internal/vpn/login.go` | `core/web_login.go` | 改 package 名；入口令牌函数改名 `PortalToken` |
| `internal/vpn/tunnel.go` | `core/protocol.go` | 改 package 名；端点类型改名 `TunnelEndpoint` |
| `internal/vpn/endpoint.go` | `core/tun_stack.go` 精简 | 只留两个回调，去掉 gvisor 接口 |

没有迁移：`core/socks.go`（删除）、`core/tun_stack.go` 的 `SetupStack` 和 gvisor 依赖（删除）、
`gui/`（删除）、旧仓库的客户端编排文件（其中的逻辑改写进 `internal/service`）。

`TunnelEndpoint` 不再实现 gvisor 的 `LinkEndpoint` 接口，只留 `OnRecv` 和 `OnDeliver`
两个回调，外加 `WriteTo` 兼容 `tunnel.go` 的调用点。

## 依赖版本（已确认存在）

| 模块 | 版本 | 用途 |
|---|---|---|
| `github.com/refraction-networking/utls` | v1.8.2 | 畸形 ClientHello 构造（与 v1.2.0 线上字节一致，已验证） |
| `golang.zx2c4.com/wireguard` | v0.0.0-20260522210424-ecfc5a8d5446 | WireGuard 用户态实现 |
| `github.com/kardianos/service` | v1.3.0 | systemd / SCM 抽象 |
| `github.com/Microsoft/go-winio` | v0.6.2 | Windows 命名管道 |
| `github.com/pquerna/otp` | v1.5.0 | TOTP 生成 |
| `gopkg.in/yaml.v3` | v3.0.1 | 配置解析 |

## 待实现

- [x] 经 HTTP 代理出站（`internal/dial`），`njuvpn probe` 可验证协议链路
- [x] `internal/config`：yaml 读取、默认值、校验
- [ ] 配置文件的权限检查（拒绝 group/other 可读）
- [ ] `internal/ipc`：`Listen`/`Dial` 的 build tag 双实现 + 行协议
- [ ] `internal/wireguard`：`TunRelay` 实现 `tun.Device` 的 7 个方法，`File()` 返回 nil
- [ ] `internal/service`：状态机 `idle / logging_in / auth_pending / connecting / up / error`
- [ ] `cmd/njuvpn`：把占位函数换成真实调用
- [ ] 地址映射：WireGuard peer 用固定地址，进出隧道时做 SNAT/DNAT 到服务端分配的内网 IP（需增量更新 IP 头与 TCP/UDP 校验和）
- [ ] 把 `StartProtocol` 里失败 5 次后的 `panic` 改成返回错误

## 已知约束

- **服务端对同一 TwfID 的并发建连有限制**：连跑 probe 会稳定复现 `unexpected query ip reply`
  （服务端返回一段固定的内存数据，首字节 0x08）。静置约 60 秒后单次运行即可通过，
  实测分配地址 172.29.56.18。这与 uTLS 版本无关，v1.2.0 与 v1.8.2 表现一致。

- **单客户端**：`QueryIp` 只返回一个隧道 IP，首包用 `ipRev` 标识，同时只能有一个 peer。
- **MTU**：隧道 1400，WireGuard 再占 32–60 字节，取 1320。
- **重启策略**：systemd unit 用 `Restart=on-failure` 而非 `always`，否则短信验证模式下会无限重启等人输码。
- **服务进程不需要 root**：WireGuard 走用户态 UDP 端口，不创建 TUN 网卡。

## 构建

```bash
go mod tidy
go build -o njuvpn ./cmd/njuvpn
```

交叉编译（本机 Linux，产物给 Windows 用）：

```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o njuvpn.exe ./cmd/njuvpn
```
