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

## 服务端建隧道受限（2026-09-09 观测，2026-09-10 更正）

同一账号在短时间内反复建立隧道后，服务端会持续拒绝 query-ip 与
tunnel-handshake，返回一段固定的 36 字节内存数据（首字节 0x03 或 0x08，
含小端栈指针）。

**更正**：先前以为 TwfID 长期有效，这个判断是错的。依据错在
portal-token 阶段——rclist.csp 不校验 TWFID（不带 Cookie 也返回同样内容），
conf.csp 用旧 TWFID 与伪造 TWFID 返回同样的 unexpected user service
(ErrorCode 20026)，所以 PortalToken 从未验证过 TWFID 是否有效。
实测旧 TwfID 已失效。

观测事实：

- 跨午夜（自然日重置）后仍然失败；
- 静置 5 分钟以上仍然失败；
- 重试越密集越失败；
- login_auth.csp 仍返回 login auth success，说明账号尚未被完全禁止登录。

旧仓库 issue #13 / #11 有对应错误码：ErrorCode 20113、"not allow to login now"、"Server forbidden access!"。

待确认：限额是滚动窗口（如 24 小时）还是服务端侧隧道会话泄漏。
区分办法：等待较长时间后重试；若仍失败，去网页版注销或联系网信中心。

对策：隧道只建立一次并长期持有；异常断开后不要立刻重连；
StartProtocol 的重试必须加退避，不能贴着上限猛冲。

## 隧道建立失败的最终定位（2026-09-10）

服务端在 TLS 握手完成后，对**任何**请求都返回同一段 36 字节内存数据：

```
080000000000000000c5100285562bdb20e4b788fe7f0000170c83a2867f000000000000
```

验证过的对照组：

- 9 种 opcode（0x00..0x08，含合法的 0x00/0x05/0x06）返回完全相同；
- 伪造 TWFID（0000000000000000）与真实 TWFID 返回完全相同；
- 全新登录的会话与复用的旧会话返回完全相同；
- 代理出口 IP 固定（日本 hy2，10/10 一致）时仍然失败。

因此这不是报文格式、会话有效性、源 IP 或频率问题——服务端没有解析
请求就在该连接上走了异常分支。字节中的 fe7f0000 / c47f0000 是小端栈
指针，整体形如进程内存快照。

同一客户端在 2026-09-09 23:32 曾完整通过全部四个阶段并分配到
172.29.56.18，之后所有尝试均失败。推测服务端侧该账号的隧道状态机
进入了不可恢复的异常，需要服务端侧重置（网页注销或联系网信中心）。

登录路径（web-login / auth-sms / portal-token）始终正常。
