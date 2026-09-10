# njuvpn

NJU VPN 的重新实现。协议层从旧仓库 `NJUConnect`（只读参考）迁移而来。

**当前状态：可用的。** 2026-09-10 实测完整协议流程通过，分配隧道地址成功。

    web-login        OK
    portal-token     OK
    query-ip         OK
    tunnel-handshake OK
    全部 4 个阶段通过，分配地址 172.29.56.18

## 1. 关键结论：直连可用，代理不可用

### 1.1 网络拓扑（2026-09-10 补充，很重要）

| 位置 | 网段 | 能否访问服务端 | 本项目 | 官方客户端 |
|---|---|---|---|---|
| 台式机（学院楼有线） | `校园网内网段`（公网，另有 IPv6） | 能，约 10ms | **03:41~03:55 成功多次** | 未测（本机无 docker） |
| 笔记本（学院楼无线） | `172.27.x.x` | **不能** | 未测 | 不能 |
| 笔记本（宿舍楼无线） | `校园网内网段` | 能 | 未测 | 成功 |
| 笔记本（手机热点） | 移动网络 | 能 | 未测 | 成功 |

**关键纠正**：官方客户端**从未在校园网内工作过**——学院楼无线 `172.27.x.x`
根本连不上服务端。此前「官方客户端在校园网能成功」的说法是错的，
那次实际是在宿舍无线或手机热点下测的。基于该前提做的推理全部作废。

反过来，本项目在**学院楼有线**（官方客户端从未测过的环境）成功建立过隧道，
因此「实现有问题」的可能性进一步降低。

未做的对照：把本项目拿到**笔记本 + 宿舍无线/手机热点**（官方客户端的成功环境）
跑一次。测试包在 `build_assets/njuvpn-laptop-test.tar.gz`，说明见包内 `说明.md`。

排查了整整一晚，根因不在协议实现，而在**出站路径**。

决定性对照（同一 TWFID、同一分钟、同一份代码）：

| 出站路径 | 结果 |
|---|---|
| 校园网直连 | **6/6 成功** |
| 经代理 | **6/6 失败**（控制码 08） |

原因是**服务端把隧道会话绑定到源 IP**：登录和建隧道必须来自同一个源 IP。

**更正（2026-09-10 04:10）**：先前把「代理出口 IP 会变」当成原因，这个归因是错的。
当时用 `icanhazip.com` 测出口，而该域名在 Clash 里没有规则，落到了默认
MATCH 组（订阅节点），测到的是订阅节点的出口，**不是 vpn.nju.edu.cn 走的路径**。
订阅节点出口确实在 IPv4 `订阅节点`（G-Core 东京）与
IPv6 `订阅节点的 IPv6` 之间轮换，但那只影响没走专属规则的目标。

`vpn.nju.edu.cn` 走的是 `校外代理` 组 → `Private Server`（个人 SS 服务器
`个人服务器`）。用最小 SS 客户端直接连该服务器实测，出口是**单一稳定的
IPv4 `个人服务器`**，不存在轮换。

补充（2026-09-10 04:00）：除了源 IP，服务端还有**隧道建立配额**。
密集重试后即使直连也会被拒，需等待若干分钟恢复。详见 2.0。
排查期间观察到的成功/失败交替，是配额与路径两个因素叠加的结果。

**该现象的解释（待最终确认）**：那台个人服务器上当时还跑着容器化的官方
客户端，它占着一条隧道会话。服务端 `Is_enable_mult_client` 为 0，
只允许同一账号一个客户端，且会话按源 IP 索引。于是：

- 经该服务器连接 → 源 IP 与容器相同（`个人服务器`）→ 冲突，被拒；
- 校园网直连 → 源 IP 是 `校园网内网段`，与容器不同 → 允许。

这与 03:50 的对照完全吻合（同一 TWFID 同一分钟：直连 6/6 成功，
经该代理 6/6 失败）。

用户已于 04:11 关闭该容器。关闭后立即重测仍失败，因为账号此时已进入
配额限制状态（见 2.0），需要等若干分钟才能区分。
**待办**：冷却后经 `Private Server` 单次测试，若通过则假设成立。

**所以：校园网内直连即可，不需要代理。**

## 2. 使用方法

### 2.0 服务端对隧道建立有配额（重要）

实测：同一账号短时间内反复建立隧道后，服务端会开始拒绝，返回控制码 03/08。
此时**登录仍然正常**（web-login / portal-token 都 OK），只有 query-ip 被拒。

恢复方式：停止请求，等若干分钟。期间任何请求都会继续被拒。

**正常使用不受影响**：一天只建几次隧道。本项目排查期间为验证协议，
在两小时内建了数十次，才触发限制。诊断时请勿反复重试，
`probe` 的 `-twf-id` 可以复用会话，但每次调用仍算一次隧道建立。

### 2.1 配置

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
  服务进程还会在**退出时无条件登出**（相当于 atexit）：`cmdRun` 里 `defer svc.Close()`，
  `RunServer` 捕获 SIGINT/SIGTERM 后停止接受连接让 `Serve` 返回。
  隧道收发协程若 panic（`StartProtocol` 失败 5 次的旧行为），
  也会先登出再 `os.Exit(1)`——协程 panic 不会触发主协程的 defer。
  登出请求带 10 秒超时，避免网络不通时卡住进程退出。
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
