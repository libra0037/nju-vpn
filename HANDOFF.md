# njuvpn

NJU VPN 的重新实现。协议层从旧仓库 `NJUConnect`（只读参考）迁移而来。

> 本仓库唯一的项目文档：架构、协议、实测结论与待办都在这里。
> 更短的介绍与快速上手见 [README.md](README.md)。

**当前状态：可用的。** 2026-09-10 实测完整协议流程通过，分配隧道地址成功。

    web-login        OK
    portal-token     OK
    query-ip         OK
    tunnel-handshake OK
    全部 4 个阶段通过，分配地址 172.29.56.18

**当前部署**：服务进程跑在笔记本的 Windows 上，客户端（Clash Verge）经 WireGuard 接入，
链路已端到端验证（见 6.9 节）。

## 1. 关键结论：直连可用，代理不可用

### 1.1 网络拓扑（2026-09-10 补充，很重要）

| 位置 | 网段 | 能否访问服务端 | 本项目 | 官方客户端 |
|---|---|---|---|---|
| 台式机（学院楼有线） | 校园网内网段（另有公网 IPv4） | 能，约 10ms | **03:41~03:55 成功多次** | 未测（本机无 docker） |
| 笔记本（学院楼无线） | `172.27.x.x` | **不能** | 未测 | 不能 |
| 笔记本（宿舍楼无线） | 校园网内网段 | 能 | 未测 | 成功 |
| 笔记本（手机热点） | 移动网络 | 能 | 未测 | 成功 |

**关键纠正**：官方客户端**从未在校园网内工作过**——学院楼无线 `172.27.x.x`
根本连不上服务端。此前「官方客户端在校园网能成功」的说法是错的，
那次实际是在宿舍无线或手机热点下测的。基于该前提做的推理全部作废。

反过来，本项目在**学院楼有线**（官方客户端从未测过的环境）成功建立过隧道，
因此「实现有问题」的可能性进一步降低。

那次对照后来做了：本项目现在就跑在笔记本上，并已端到端打通（见 6.9 节）。

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
订阅节点出口确实在多个地址之间轮换（IPv4 与 IPv6 都有，例如 G-Core 东京），
但那只影响没走专属规则的目标。

`vpn.nju.edu.cn` 走的是 `校外代理` 组 → `Private Server`（一台个人服务器）。
用最小 SS 客户端直接连该服务器实测，出口是**单一稳定的
IPv4 地址**，不存在轮换。

补充（2026-09-10 04:00）：除了源 IP，服务端还有**隧道建立配额**。
密集重试后即使直连也会被拒，需等待若干分钟恢复。详见 2.0。
排查期间观察到的成功/失败交替，是配额与路径两个因素叠加的结果。

**当时对该现象的解释（未证实）**：那台个人服务器上跑着容器化的官方客户端，
占着一条按源 IP 索引的隧道会话（`Is_enable_mult_client` 为 0，同一账号只允许一个客户端），
于是经它连接会冲突。

后来在那台服务器上实测官方客户端也能建立隧道，这个解释因此站不住脚。
可以确定的只有协议层的硬约束：**登录与建隧道必须来自同一个源 IP**，
这也正是「校园网内直连即可、不要走代理」的由来。代理路径当时 6/6 失败的确切原因
没有再查清（当时账号已同时进入配额限制，两个因素叠加）。

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
    go run ./cmd/njuvpn status -config config.yaml
    go run ./cmd/njuvpn stop -config config.yaml

    # 注：start 会自己把口令（配置里没写时）与验证码问完，不再有 auth 子命令。
    # 管道也可以：printf '%s\n%s\n' "$PASSWORD" "$CODE" | njuvpn start

    # 注：系统服务安装（service install/start）已决定移除，
    # 改为 CLI 按需拉起 + njuvpn restart，见第 10 节。

### 2.2 构建

    go build -o njuvpn ./cmd/njuvpn                    # 本平台
    GOOS=windows go build -o njuvpn.exe ./cmd/njuvpn  # 交叉编译给 Windows

## 3. 架构

一个二进制，两个角色：服务进程、命令行客户端（现状另有 `service` 子命令用于安装系统服务，已决定移除，见第 10 节）。
承载层用 WireGuard（wireguard-go）：服务进程不需要 root、不建 TUN 网卡，
客户端（sing-box / Clash.Meta 等）用自带用户态网络栈接入。

    cmd/njuvpn/main.go        子命令分发与参数解析
    cmd/njuvpn/client.go      CLI 侧的 IPC 调用
    internal/vpn/             协议层（portal 登录 / connect / tunnel / session / totp / parse / control）
    internal/dial/            出站拨号（直连/HTTP CONNECT/SOCKS5）
    internal/config/          配置读取与校验
    internal/ipc/             本地通信（unix socket / 命名管道）+ 行协议
    internal/wireguard/       tun.Device 实现与地址映射（SNAT/DNAT + 校验和增量修正）
    internal/service/         状态机、隧道生命周期、IPC 服务端（系统服务安装已决定删除，见第 10 节）
    internal/vpntest/         测试替身（脚本化 portal + 内存隧道服务端）

代码约 6300 行（2026-09-10 实测 6274 行），另有约 3600 行测试；`go build` / `go vet` / `go test` 全通过，Linux 与 Windows 交叉编译通过。

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
- **服务端单客户端**：`Is_enable_mult_client` 为 0，同一账号同时只能有一个隧道会话，
  且会话按源 IP 索引（登录与建隧道必须同源）。异常退出会留下占名额的会话 ——
  这正是下面「退出时无条件登出」的由来。
- **登出**：`GET /por/logout.csp` 需携带有效 TWFID。`Stop` 与 `fail` 都会先登出再释放资源。
  服务进程还会在**退出时无条件登出**（相当于 atexit）：`cmdRun` 里 `defer svc.Close()`，
  `RunServer` 捕获 SIGINT/SIGTERM 后停止接受连接让 `Serve` 返回。
  隧道与命令处理都在 actor 协程里运行，panic 由该协程的 recover 兜住
  并收敛成一次失败（不会再带走进程）。登出请求带 10 秒超时，
  避免网络不通时卡住进程退出。
- **服务端并发限制**：同一 TWFID 短时间反复建连会被拒，重试越密越失败。probe 只保留 3 次 × 30 秒退避。
- **日志**：不得打印密码、密文、TWFID 明文（已有 `redact`，勿回退）。

## 6. 硬性约束

- **仓库内不得出现厂商与产品字眼**（含 git 历史）。提交前遍历全部历史自检：
  用 `git rev-list --all` 取所有提交，对每个提交跑 `git grep` 匹配词表。
  词表由用户单独维护，不在仓库内保存。
- **旧仓库 `NJUConnect` 只读**。
- **凭据不入库**。`config.yaml` 已在 `.gitignore`，权限 600。

## 6.5 线上格式已被 golden 测试与实测钉住

重构后新增 `internal/vpn/wire_format_test.go`：把隧道 ClientHello 的三个参数、
流握手帧（64 字节）、query-ip 帧（64 字节）、token 布局、地址反序全部写成常量断言。
这些值都是从旧实现逐字节核对过的，改动后会立刻失败。

2026-09-10 于宿舍网段实测（不消耗账号配额，见 `internal/vpn/live_hello_test.go`）：

| 构造 | 服务端反应 | 结论 |
|---|---|---|
| 隧道 ClientHello（TLS1.1 + RC4-SHA + SessionId 以 L3IP 开头） | 握手成功，约 5ms | 可用 |
| 同样构造但 SessionId 换成 NOPE | `remote error: tls: handshake failure` | **L3IP 是判别位** |
| 同样构造但版本改成 TLS 1.2 | `server selected unsupported protocol version 302` | 服务端强制 TLS 1.1（0x0302） |
| 同样构造但 SessionId 为空 | `remote error: tls: handshake failure` | 那个 SessionId 不能省 |
| 普通 ClientHello（HelloGolang） | 握手成功 | 443 端口同时服务 Web 登录，因此普通 TLS 成功是正常的 |

注意最后一行：**"普通 TLS 也能握手成功"是预期行为**，不能据此认为服务端不区分隧道；
真正的判别依据是上面第二行的反例。

登录页实测：2431 字节、12ms，返回的 TwfID 恰好 16 字节（与 token 布局假设一致），
RSA 公钥 2048 位、指数 65537，CSRF 码 9 字节。

## 6.6 端到端实测结果（2026-09-10 宿舍网段）

台式机 + 校园网直连，完整走通：

```
18:59:25  start            登录页 → 口令登录 → 服务端要求短信
18:59:26  短信接口响应     SmsSendInterval=178（倒计时重置 ⇒ 真的发了短信）
19:00:02  auth 382933     短信校验通过
19:00:02  portal-token    Server Session ID: 32 字节
19:00:02  query-ip        分配 172.29.56.18
19:00:02  上行流/下行流    握手均被接受
19:00:02  状态 up         校园网地址 172.29.56.18，peer 10.66.66.2
19:00:34  stop            logout user success（服务端会话已释放）
```

同一天早些时候还成功分配过别的地址，说明隧道地址是轮换分配的。

**注意 `up` 的准确含义**：它表示校园网隧道通了（真机已验收到服务端分配的地址），（登录、token、
query-ip、两条流都在）。WireGuard 承载层已经在监听（见 6.7 节），此时已可从客户端接入。

### 短信接口的语义（踩坑记录）

`/por/login_sms.csp` 在冷却期内**把上次的响应原样返回**，连 `T_SMSINFOR`
里"验证码已发送到您的手机"这句话都不改，只有倒计时不同：

| 时刻 | SmsSendInterval | 实际结果 |
|---|---|---|
| 18:56:15 | 179 | 真发了（用户收到） |
| 18:57:31 | 102 | 没发（用户没收到，但程序提示"已发送"） |
| 18:58:24 | 48 | 没发 |
| 18:59:26 | 178 | 真发了（用户收到） |

结论：**唯一可靠判据是倒计时是否重置到窗口顶部**（窗口实测约 180 秒，
取 150 秒为阈值）。按 `ErrorCode=1` 或文案判断都会在冷却期骗用户去等
一条不会来的短信。`ErrSMSSent` / `ErrSMSStillValid` 的区别就是为此而设。

### 二次验证续用会话时的一个坑（已修）

`start` 停在 `auth_pending` 后，提交验证码会新建一个 Session 对象，
而它与 `start` 留下的那个**共用同一个 TwfID**（`login_sms1.csp` 不返回新
TwfID 时沿用原值）。如果按"释放上一个会话"处理，登出会把正在续用的会话
一起杀掉：日志里表现为 `logout user success` 紧跟着上行流被服务端以
Shutdown(8) 拒绝。现在 `attach` 与 `auth` 都会识别"同一个服务端会话"，
只释放本地资源、不登出。

## 6.7 WireGuard 承载层（已接线）

承载层用的是用户态 wireguard-go，**不创建 TUN 网卡、不需要 root**：

    Clash Verge / sing-box（客户端，自带用户态网络栈）
      ↕ WireGuard UDP（默认 51820）
    wireguard-go Device（本进程）
      ↕ internal/wireguard.Relay：内存里的 tun.Device，按 IPv4 总长度分帧
      ↕ internal/wireguard.Mapper：peer 地址 ↔ 校园网分配的地址，含校验和增量修正
      ↕ 校园网隧道（TLS 上的私有协议）

关键点：

- 私钥留空时首次启动自动生成、按 RFC 7748 夹紧，并**就地写回配置文件**
  （只替换 private_key 那一行，注释与其它字段原样保留）。启动日志会打印
  服务端公钥，客户端配置要用它。
- UAPI 里的密钥是**十六进制**，配置文件里是 **base64**，两者不能混。
- 客户端 Outbound 需要这三项：服务端公钥、peer 地址（默认 10.66.66.2）、
  以及 `allowed_ips` 用 0.0.0.0/0。这样默认路由才走隧道，流量才会被承载层
  改写后送进校园网。
- 从校园网里到不了这台机器时（笔记本与台式机不在同一网段），UDP 有两个办法：
  一是让它走已有的 SOCKS/HTTP 隧道转发 UDP；二是在本机用 `socat`/
  `udp2raw` 之类的工具把 UDP 映射到一条已打通的 TCP 通道上。
  目前实现里 `wireguard.listen_port` 只在本机监听，没有走代理。

- **与旧实现的差异**：旧仓库（`NJUConnect`）自带 SOCKS5 服务与 gvisor 用户态
  网络栈，本实现两者都不迁移 —— 承载改用 WireGuard，网络栈交给客户端（Clash / sing-box
  自带），因此依赖里没有 gvisor。协议层（`internal/vpn`）从旧仓库迁移并重写。

验证方式：`internal/wireguard/loopback_test.go` 用一台真实的 wireguard-go 设备
（客户端）+ 内存 TUN 做回环，覆盖握手、加密、双向包转发、地址改写、
未授权客户端被拒、Close 后停止转发。不需要网卡也不需要 root。

## 6.8 UDP 监听范围（默认只监听回环）

同机方案下服务端与客户端在同一台机器上，没有理由把隧道端口暴露给整个局域网。
wireguard-go 自带的绑定用的是 `":port"`（即 0.0.0.0:port），所以
`internal/wireguard/bind.go` 里自己实现了一个最小 `conn.Bind`：

- 只 `ListenUDP` 在 `127.0.0.1`，批量大小固定 1，不用 GSO/PKTINFO/SO_MARK
- 端点直接复用上游的 `conn.StdNetEndpoint`，行为一致
- 关闭后接收函数返回 `net.ErrClosed`，设备的接收协程能正常退出

配置项 `wireguard.listen_host`：

| 取值 | 含义 |
|---|---|
| `loopback`（默认，也接受 `local` / `127.0.0.1`） | 只绑 127.0.0.1，同机客户端用这个 |
| `all`（也接受 `any` / `0.0.0.0`） | 绑全部网卡，需要其他机器接入时用 |

拼错的值会被拒绝，不会静默放开监听范围（配置校验与 `wireguard.ParseListenHost`
两处都要能识别；因为依赖方向的原因，配置包里重复了一份取值集合）。

验证方式不是发包探测，而是"能不能在同一个端口的另一个地址上再绑一次"：
绑到 0.0.0.0 时再绑具体地址会 EADDRINUSE，只绑回环时绑其他本机地址仍然成功。
`bind_test.go` 里既有绑定层的用例，也有设备层的用例
（`TestDeviceBindsOnlyLoopbackByDefault`），确保设备真的用了这个绑定。

## 6.9 端到端打通（2026-09-10 晚，笔记本 + Clash Verge）

**链路已被验证可用**：Clash Verge（mihomo v1.19.25）→ WireGuard 出站 →
njuvpn 承载层（127.0.0.1:51820）→ 校园网隧道 → 校园网。

验证方法（只读，不改配置）：用 mihomo 的 API 对该出站做延迟测试——
它会让请求**真的穿过这条出站**，成功即证明整条链路成立：

```
GET /proxies/njuvpn-campus/delay?timeout=8000&url=https://www.nju.edu.cn
  Authorization: Bearer <secret>

njuvpn-campus → https://www.nju.edu.cn : 7ms
njuvpn-campus → http://www.nju.edu.cn  : 3ms
Private Server → https://www.nju.edu.cn : 33ms（对照，走上海代理）
```

3-7ms 与本机到服务端的往返一致，说明请求确实经过了隧道。

### 部署位置：Windows，不是 WSL（重要）

这台笔记本的 WSL 用 `networkingMode=VirtioProxy`（不是 mirrored），实测：

| 方向 | 结果 |
|---|---|
| WSL → Windows `127.0.0.1`（TCP/UDP） | 通 |
| Windows → WSL `127.0.0.1`（TCP） | 通 |
| Windows → WSL `127.0.0.1`（**UDP**） | **不通** |
| Windows → WSL 局域网地址（UDP） | 不通 |

WireGuard 只能走 UDP，所以客户端在 Windows 时，服务进程也必须跑在
Windows 上（Clash 与它同机走 loopback UDP）。宿主是 Win10，
njuvpn.exe 直接运行即可，不需要管理员权限、不建网卡。

WSL 侧仍可用于开发与跑测试（`go test./...` 全绿），只是不能承载这条路。

（这是这台笔记本 WSL 网络模式的限制，不是项目限制：**原生 Ubuntu 上服务进程就跑在本机，
没有跨 WSL 边界的 UDP 问题**。Windows 与 Linux 都是目标平台，见第 10 节。）

### 两个查错时踩过的坑（别再犯）

1. **`Get-CimInstance Win32_Process` 的 Read/WriteTransferCount 不是网络流量**，
   它是进程的文件 I/O 计数。用它判断"隧道有没有搬包"会得到完全错误的结论。
   要判断承载层是否在工作，用 mihomo 的延迟测试，或给设备加统计。
2. **不要用 grep Clash 的配置文件来判断节点是否存在**：Clash Verge 的运行配置
   由 GUI 重新生成，位置和时机都不受我们控制。要查就查 mihomo 的 API
   （`/proxies`），那才是运行时的事实。

### 用户侧配置（Clash Verge，通过 profile 的 proxies 扩展文件）

```yaml
- name: njuvpn-campus
  type: wireguard
  server: 127.0.0.1
  port: 51820
  ip: 10.66.66.2
  private-key: <客户端私钥>
  public-key: <服务端公钥，njuvpn 启动日志里打印>
  allowed-ips: ["0.0.0.0/0"]
  udp: true
  mtu: 1320
```

`allowed-ips` 必须是 0.0.0.0/0，否则默认路由不进隧道。
`ip` 必须与服务端的 `peer_address` 一致。

## 7. 参考实现（协议对照）

1. **sunnysab/smelly-connect**（Rust）— 含 `smelly-tls`，从零实现的 TLS 1.1 客户端。
2. **Yan233th/SHIEP-Pipeline**（Rust）— 含完整控制码表与流握手逻辑。

两者报文格式与本项目逐字节一致，可作为协议对照。
注意：这两个项目含本仓库禁止出现的字眼，只作只读参考，不要带任何字眼或代码片段进来。

## 8. 待办

进行中：

- [ ] 隧道重连期间的状态显示（见第 10 节）、vpntest 的时序等待、
      F 组 16 条简化
- [ ] 在 Ubuntu 真机跑通（服务进程 + 客户端接入）
- [ ] 开机自启：Windows 任务计划程序 / Linux systemd user unit

已完成：

- [x] 端到端联调：服务进程 start → auth → up → Clash Verge 接入（见 6.9 节）
- [x] WireGuard 私钥首次启动自动生成并写回配置
- [x] 协议层与服务层的健壮性重构（见第 9 节）
- [x] 配置文件权限检查（改代码时按 G1 删除）
- [x] 一轮逐条代码审查的修复（协议边界、错误路径、死代码、单用户假设下的取舍）
- [x] 新形态在 Windows 上端到端跑通（见第 11 节）

## 9. 重构后的结构

一次针对「错误路径」的重构，目标是把三类事故堵死：对端给了意外数据就 panic、
错误路径泄漏连接、状态被并发操作搅乱。

### 分层

| 包 | 职责 |
|---|---|
| `internal/vpn` | 协议层。`Connect` 完成登录并返回 `*Session`；`Session` 持有 TwfID、query-ip 连接与两条数据流，`Run`/`RunWithRetry` 负责转发，`Close` 幂等收尾并登出 |
| `internal/service` | actor 模型：所有改状态的操作经 `cmds` 通道串行执行，状态快照单独加锁、只读查询永不阻塞 |
| `internal/ipc` | 行协议（有长度上限与读写超时）。端点权限校验与连接数上限已决定删除（G2 / G4） |
| `internal/wireguard` | `tun.Device` 实现：按 IPv4 总长度分帧，按需改写地址 |
| `internal/vpntest` | 测试替身：脚本化 portal 与内存隧道服务端 |

### 几条硬规则（改动时不要破坏）

1. **协议层不许 panic**：所有从服务端响应取值的地方走 `requireTag` / `tagValue`，长度不足返回 `*ProtocolError`。曾经有四处 `FindSubmatch(...)[1]`、一处 `HandshakeState.ServerHello.SessionId`、一处 `(*[48]byte)([]byte(token+twfID))`，每一个都能一次带走整个进程。
2. **失败路径也要交出会话**：`Connect` 在部分失败时返回非 nil 的 `*Session`，调用方必须 `Close`，否则服务端名额不会释放。
3. **一切 I/O 可取消**：`Connect`、隧道重连、登出、IPC 调用都有 ctx 或超时。
4. **连接所有权唯一**：连接由 `Session` 持有并统一关闭；`openStream` / `queryIP` 的每条错误路径都先关连接——曾经 query-ip 失败返回 `(nil, nil, err)`，调用方的清理代码永远是死代码。
5. **状态只能由 actor 改**：隧道协程的退出报告带代次（gen），过期代次一律忽略，否则旧协程会把刚建立的新会话拆掉。

### 回归测试

`go test ./... -race` 不连任何真实服务端：假 portal 是注入的 `RoundTripper`，假隧道是注入的 `net.Pipe`，都在 `internal/vpntest` 里。覆盖的回归点：畸形响应不 panic、SessionId 过短不越界、复用会话时验证码确实提交、部分失败仍能登出、并发 Close 只登出一次、退避能响应 ctx 取消、流断开后另一条也收敛、Close 不被长 I/O 阻塞、panic 不带走进程、IPC 超长行与配置权限。

## 10. 进程模型与路径（2026-09-10 已实现）

来源：一轮逐条代码审查后的取舍。这一节记录**改完之后**的形态。

### 平台

Windows 与 Linux 都要能用 —— Linux 侧不是「只用来跑测试」，用 Ubuntu 做主力机的人应该能直接部署。

### 进程模型：CLI 按需拉起，没有系统服务

- `njuvpn start` 先探活，连不上就以脱离终端的方式拉起 `njuvpn run`（记日志到配置同目录），
  再轮询到就绪。**只影响 start / restart**：stop / status / auth / wg-* 不会拉起服务。
- `njuvpn restart` = 请服务进程收尾退出（含登出）→ 等端点不再响应 → 重新拉起。
  改完配置用它，不要手工杀进程（手工杀会跳过登出，服务端名额要等超时才释放）。
- 服务进程的退出有两条路径：系统信号（Ctrl-C / systemd / 任务计划程序）与 IPC 的 `shutdown`。
  两条都走到同一个 `RunServer` 返回处，由 `cmdRun` 的 `defer svc.Close()` 完成登出。
- 开机自启按需另配：Windows 用任务计划程序「登录时启动」；Linux 手写 systemd user unit
  （`~/.config/systemd/user/njuvpn.service`，要免登录也运行再加 `loginctl enable-linger`）。
- 已删掉：`njuvpn service ...`、`internal/service/install.go`、`windowsProgram`、kardianos 依赖。
  理由：服务进程不需要任何特权（6.9 节实测，普通会话即可）。以 SCM 跑会落到 LocalSystem，
  命名管道的 DACL 里不含交互用户，五个子命令在 connect 阶段全被拒。

### 路径

- 配置文件：Windows 用 `%LOCALAPPDATA%` 下的 njuvpn 目录，Linux 用 `~/.config/njuvpn/config.yaml`
  —— 原来的 `/etc/njuvpn/config.yaml` 与 ProgramData 都以特权运行为前提，随之作废。
- IPC 端点：按配置文件的路径派生（`ipc.EndpointFor`）。Linux 是
  `$XDG_RUNTIME_DIR/njuvpn-<实例标识>.sock`（取不到时回落到该用户的私有临时目录），
  Windows 是 `\\.\pipe\njuvpn-<实例标识>`。同一份配置永远得到同一个端点，
 不同配置互不相干，多实例因此不会误伤彼此。
- 服务日志：配置文件同目录的 `njuvpn-<配置名>.log`（被拉起的服务进程没有控制台）；
  名字里带配置名，同目录的多份配置不共用一份日志。

### 安全取舍

个人使用、单用户机器：只对「同机其他用户 / 同机敌意进程」成立的加固不做 ——
配置文件权限校验（G1）、IPC 对端校验（G2）、argv 可见性（G3）、连接数上限（G4）。
命名管道 DACL（G5）保留，只把注释改成「只让当前用户与管理员访问」。

## 11. 新形态的端到端实测（2026-09-10 晚，笔记本 Windows）

部署方式：本机 `GOOS=windows go build` → scp 到笔记本 → 换掉旧二进制。
配置从程序目录移到 `%LOCALAPPDATA%\njuvpn\`（默认路径已改，见第 10 节）。

先做了一次**不耗短信**的冒烟测试，确认新的生命周期在 Windows 上成立：

```
njuvpn.exe restart
  服务进程未在运行（...），直接拉起
  已拉起服务进程（日志: %LOCALAPPDATA%\njuvpn\njuvpn.log）
  服务进程已重启          142ms（含探活 + 拉起 + 轮询就绪）
njuvpn.exe status   →   idle
```

然后走完整链路（用户操作，22:19–22:20）：

```
22:19:08  start            登录页 → 口令登录 → 服务端要求短信
22:19:09  短信接口         倒计时 178 秒（判据：重置到窗口顶部 ⇒ 真的发了）
22:19:21  auth            短信验证码校验通过
22:19:21  portal-token    Server Session ID: 32 字节
22:19:21  承载层          WireGuard 承载已启动: UDP 51820（仅本机），peer 10.66.66.2
22:19:21  状态 up         校园网地址 172.29.56.18
22:20:04  stop            logout user success（服务端会话已释放）
```

结论：**CLI 按需拉起 + 热更新的承载层在 Windows 上工作正常**，Clash 侧配置无需改动
（服务端公钥与私钥都从原配置继承）。

## 12. Ubuntu 22.04 实测（2026-09-10 晚，临时测试机）

环境：校外云服务器，Ubuntu 22.04.5、x86_64、2 vCPU、用户级 systemd 可用。
该机 DNS 能解析 `vpn.nju.edu.cn`（→ `202.119.32.69`）、直连 443 返回 200、出口固定。
**这台机器只是测试用的校外环境，不做实际部署**，测完已清理（见文末）。

### 验证结果

| 项目 | 结果 |
|---|---|
| 测试套件 | 8 个包全部通过（配置 / IPC / 替身 / 拨号 / 服务 / 协议 / 承载 / CLI） |
| 承载层回环测试 | 通过：真实 wireguard-go 设备 + 内存 TUN，握手、加密、双向转发、地址改写 |
| 按需拉起 | `restart` 在 0.14s 内拉起服务进程；`PPID=1`、独立会话、无终端 |
| 端点 | `/run/user/1000/njuvpn.sock`，模式 `srw-------`（0600） |
| 用户级 unit | `systemctl --user start njuvpn` 起来后 CLI 能连上、journal 有日志 |
| 信号退出 | `kill -TERM` 走与 systemd 相同的收尾路径（日志：收到信号 terminated，准备退出） |
| 隧道建立 | `auth` 后 `up`，拿到校园网分配的地址 |
| UDP 监听 | `ss` 确认只绑 `127.0.0.1:51820`（与 6.8 节一致） |
| 私钥自举 | 首次启动生成、夹紧、就地写回 `~/.config/njuvpn/config.yaml` |
| 登出 | `stop` 后服务端返回 `logout user success`，名额释放 |

### 两处平台差异（都已在实测中修正）

1. **端点默认值**：原来的 `/run/njuvpn.sock` 普通用户写不进去，配置里留空即用
   `$XDG_RUNTIME_DIR`（见第 10 节）。测试时配置里的旧值需要删掉。
2. **开机自启**：unit 的 `WantedBy=default.target`，而默认 `Linger=no` ——
   要免登录常驻需要 `loginctl enable-linger <user>`（需提权，本次未做）。

### 没验证到的部分

承载层的**客户端接入**没测：配置里 `peer_public_key` 为空，`wg-stats` 报
「承载层没有接入的 peer」；而 UDP 只绑回环，外部客户端也连不进来。
要验证需要两步：`listen_host: all` + 云安全组放行 UDP，以及
`njuvpn wg-peer <客户端公钥>`（热更新，不重建隧道、不耗短信）。

### 测试机的清理

- 删 `~/.config/systemd/user/njuvpn.service`（先 `systemctl --user stop`）
- 删除 `~/.config/njuvpn/`（配置里有账号口令，日志一并删）
- 删除测试二进制目录 `~/njt`（67MB）
- 保留 `~/njuvpn/njuvpn`（只读二进制，不含凭据），下次测试可直接用
