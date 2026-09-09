# njuvpn

NJU VPN 的重新实现。协议层从旧仓库 `NJUConnect`（只读参考）迁移而来。

**当前状态：可用的。** 2026-09-10 实测完整协议流程通过，分配隧道地址成功。

    web-login        OK
    portal-token     OK
    query-ip         OK
    tunnel-handshake OK
    全部 4 个阶段通过，分配地址 172.29.56.18

## 1. 关键结论：直连可用，代理不可用

排查了整整一晚，根因不在协议实现，而在**出站路径**。

决定性对照（同一 TWFID、同一分钟、同一份代码）：

| 出站路径 | 结果 |
|---|---|
| 校园网直连 | **6/6 成功** |
| 经代理 | **6/6 失败**（控制码 08） |

原因是**服务端把隧道会话绑定到源 IP**。登录和建隧道必须来自同一个源 IP。
实测代理的出口 IP 会在连接间变化（订阅节点存在 IPv4 `订阅节点` 与
IPv6 `订阅节点的 IPv6` 两套出口），两条连接走不同出口就会被判定为会话不匹配。

**所以：校园网内直连即可，不需要代理。** 若必须经代理，代理必须提供稳定且唯一的出口 IP。

## 2. 使用方法

校园 DNS 解析不了 `vpn.nju.edu.cn`，所以直连时需要指定 IP：

    server: vpn.nju.edu.cn
    server_ip: 202.119.32.69   # 实际建连用这个地址，Host 头仍用域名
    proxy: ""                  # 直连

命令：

    # 协议探测（-twf-id 可复用会话，跳过短信）
    go run ./cmd/njuvpn probe -config config.yaml [-twf-id <id>] [-debug]

    # 服务进程 + 命令行客户端
    go run ./cmd/njuvpn run -config config.yaml &
    go run ./cmd/njuvpn start -config config.yaml
    go run ./cmd/njuvpn auth <code> -config config.yaml
    go run ./cmd/njuvpn status -config config.yaml
    go run ./cmd/njuvpn stop -config config.yaml

    # 操作系统服务
    sudo ./njuvpn service install -config /etc/njuvpn/config.yaml
    sudo ./njuvpn service start

## 3. 架构

一个二进制，三个角色：服务进程、命令行客户端、系统服务管理。
承载层用 WireGuard（wireguard-go）：服务进程不需要 root、不建 TUN 网卡，
客户端（sing-box / Clash.Meta 等）用自带用户态网络栈接入。

    cmd/njuvpn/main.go        子命令分发与参数解析
    cmd/njuvpn/client.go      CLI 侧的 IPC 调用
    internal/vpn/             协议层（login/tunnel/logout/probe/totp/endpoint/client）
    internal/dial/            出站拨号（直连/HTTP CONNECT/SOCKS5）
    internal/config/          配置读取与校验
    internal/ipc/             本地通信（unix socket / 命名管道）+ 行协议
    internal/wireguard/       tun.Device 实现与地址映射（SNAT/DNAT + 校验和增量修正）
    internal/service/         状态机、隧道生命周期、IPC 服务端、系统服务安装

代码约 3300 行，`go build` / `go vet` / `go test` 全通过，Linux 与 Windows 交叉编译通过。

## 4. 协议要点

- 隧道用 uTLS 构造刻意畸形的 ClientHello：TLS 1.1、RC4-SHA、SessionId 以 `L3IP` 开头。
  服务端 443 端口同时承载 Web 登录与隧道，靠 ClientHello 特征区分；非 L3IP 连接会被直接拒握手。
- token 48 字节 = portal 会话的 31 字节十六进制 + `\x00` + 16 字节 TWFID。
  两种取法都可用：标准 HTTPS 连接的 ServerHello SessionId，或 legacy L3IP 连接的 ServerHello。
- 服务端响应是 4 字节小端控制码 + 32 字节数据。控制码：0 SendIp（成功，后跟 IP）、
  1/2 RxAck/TxAck、3 ServerReset、5 IpBusy、8 Shutdown、9 IpConflict、14 IpKick。
- query-ip 建立的连接必须保持打开到隧道握手完成。

## 5. 已知坑

- **短信状态**：响应的 `IS_IN_PERIOD`、`SmsSendInterval`、`g_DisableTime` 是「本次发送后
  前端按钮的禁用倒计时」，**不是**「没重发」。`ErrorCode=1` + 带手机号即表示已发送。
- **Go 的 nil 接口**：`QueryIp` 失败返回 nil 的 `*tls.UConn`，赋给 `net.Conn` 会得到
  非 nil 接口，`Close()` 会崩。已修，勿回退。
- **登出**：`GET /por/logout.csp` 需携带有效 TWFID。`Stop` 与 `fail` 都会先登出再释放资源。
- **服务端并发限制**：同一 TWFID 短时间反复建连会被拒，重试越密越失败。probe 只保留 3 次 × 30 秒退避。
- **日志**：不得打印密码、密文、TWFID 明文（已有 `redact`，勿回退）。

## 6. 硬性约束

- **仓库内不得出现厂商与产品字眼**（含 git 历史）。提交前遍历全部历史自检：
  用 `git rev-list --all` 取所有提交，对每个提交跑 `git grep` 匹配词表。
  词表由用户单独维护，不在仓库内保存。
- **旧仓库 `NJUConnect` 只读**。
- **凭据不入库**。`config.yaml` 已在 `.gitignore`，权限 600。

## 7. 参考实现（协议对照）

1. **sunnysab/smelly-connect**（Rust）— 含 `smelly-tls`，从零实现的 TLS 1.1 客户端。
2. **Yan233th/SHIEP-Pipeline**（Rust）— 含完整控制码表与流握手逻辑。

两者报文格式与本项目逐字节一致，可作为协议对照。
注意：这两个项目含本仓库禁止出现的字眼，只作只读参考，不要带任何字眼或代码片段进来。

## 8. 待办

- [ ] 端到端联调：服务进程 `start` → `auth` → 状态 `up` → WireGuard 客户端接入
- [ ] `StartProtocol` 失败 5 次后仍会 `panic`，服务进程里应改为返回错误
- [ ] 配置文件的权限检查（拒绝 group/other 可读）
- [ ] WireGuard 私钥首次启动自动生成并写回配置
- [ ] 真机验证 `service install` 与 systemd 单元

