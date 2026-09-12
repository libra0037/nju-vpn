# njuvpn

南京大学校园网 VPN 的重新实现。协议层从旧仓库 `NJUConnect`（只读参考）迁移而来。

> 项目主文档：协议要点、架构与设计取舍都在这里；安装与使用见 [README.md](README.md)。

## 1. 现状

**可用。** 协议四个阶段（web-login → portal-token → query-ip → 流握手）走通并拿到服务端分配的校园网地址；承载层把隧道出口接到本机 UDP 端口，客户端接入已端到端验证。

| 场景 | 结果 | 来源 |
|---|---|---|
| Windows + Clash Verge（用户态 WireGuard 出站） | 链路打通，请求经隧道到达校内 | 2026-09-10 实测 |
| 校外 Ubuntu + 内核 WireGuard 客户端 | 1 秒内握手，ping 校内 30 包 0 丢失，出口 IP 变成教育网地址 | 2026-09-12 实测 |
| Ubuntu 服务进程侧 | 按需拉起、端点权限、信号退出、私钥自举、登出全部通过 | 2026-09-10 实测 |

服务进程不需要 root，也不创建网卡。

## 2. 协议要点

- 隧道用 uTLS 构造刻意畸形的 ClientHello：TLS 1.1、RC4-SHA、SessionId 以 `L3IP` 开头。443 端口同时承载 Web 登录与隧道，服务端靠这些特征区分；非 L3IP 的连接会被直接拒绝握手。
- 判别位就是 SessionId 的前缀（来源：2026-09-10 live_hello 实测）：换成别的写法或留空都会被拒握手；版本改成 TLS 1.2 会被服务端以 unsupported protocol version 拒掉，说明它强制 TLS 1.1。普通 TLS（HelloGolang）也能握手成功，那是 Web 登录那一侧的正常表现，不能据此认为服务端不区分隧道。
- token 48 字节 = portal 会话的 31 字节十六进制 + `\x00` + 16 字节 TWFID。两种取法都可用：标准 HTTPS 连接的 ServerHello SessionId，或 legacy L3IP 连接的 ServerHello。
- 服务端响应是 4 字节小端控制码 + 32 字节数据。控制码：0 SendIp（成功，后跟 IP）、1/2 RxAck/TxAck、3 ServerReset、5 IpBusy、8 Shutdown、9 IpConflict、14 IpKick。
- query-ip 建立的连接必须保持打开到隧道握手完成。
- 登录页里的 TWFID 恰好 16 字节；RSA 公钥 2048 位、指数 65537。
- 线上格式由 golden 测试钉住：`internal/vpn/wire_format_test.go` 把 ClientHello 参数、流握手帧（64 字节）、query-ip 帧、token 布局与地址反序都写成常量断言。这些值逐字节核对过旧实现，改动会立刻失败。

### 2.1 服务端对隧道建立有配额

同一账号短时间内反复建立隧道后，服务端开始拒绝（控制码 03/08）：**登录仍然正常**，只有 query-ip 被拒。恢复方式是停止请求、等若干分钟，期间任何请求都会继续被拒。（来源：2026-09-10 排查事故）

诊断时不要反复重试：`probe -twf-id` 能复用会话，但每次调用仍算一次隧道建立。正常使用不受影响，一天建几次隧道而已；这条限制是排查期间两小时建了数十次才触发的。

### 2.2 短信验证的语义

`/por/login_sms.csp` 在冷却期内**把上次的响应原样返回**，连「验证码已发送到您的手机」这句文案都不改，只有倒计时不同。唯一可靠的判据是倒计时是否重置到窗口顶部（冷却窗口实测约 180 秒，代码取 150 秒为阈值）：按 `ErrorCode=1`、有没有手机号、或那句文案判断，都会在冷却期骗用户去等一条不会来的短信。`ErrSMSSent` / `ErrSMSStillValid` 的区别就是为此而设。（来源：2026-09-10 实测）

### 2.3 二次验证续用会话时的坑

`start` 停在 `auth_pending` 后提交验证码会新建一个 Session 对象，而它与 `start` 留下的那个**共用同一个 TWFID**（`login_sms1.csp` 不返回新 TWFID 时沿用原值）。若按「释放上一个会话」处理，登出会把正在续用的会话一起杀掉，表现为 `logout user success` 紧跟着上行流被服务端以 Shutdown(8) 拒绝。现在 `attach` 与 `auth` 都会识别「这是同一个服务端会话」，只释放本地资源、不登出。

### 2.4 up 的准确含义

`up` 表示校园网隧道通了：登录、token、query-ip、两条流都在，并已收到服务端分配的地址。WireGuard 承载层此时在监听，客户端已经可以接入（前提是配置里给了 peer 公钥，见 §4）。

## 3. 架构

一个二进制，两个角色：服务进程、命令行客户端。

    cmd/njuvpn/main.go        子命令分发与参数解析
    cmd/njuvpn/client.go      CLI 侧的 IPC 调用
    internal/vpn/             协议层（portal 登录 / connect / tunnel / session / totp / parse / control）
    internal/dial/            出站拨号（直连/HTTP CONNECT/SOCKS5）
    internal/config/          配置读取与校验
    internal/ipc/             本地通信（unix socket / 命名管道）+ 行协议
    internal/wireguard/       tun.Device 实现与地址映射（SNAT/DNAT + 校验和增量修正）
    internal/service/         状态机、隧道生命周期、IPC 服务端
    internal/vpntest/         测试替身（脚本化 portal + 内存隧道服务端）

代码约 7800 行，另有约 6200 行测试（2026-09-12 实测）。

### 3.1 分层

| 包 | 职责 |
|---|---|
| `internal/vpn` | 协议层。`Connect` 完成登录并返回 `*Session`；`Session` 持有 TWFID、query-ip 连接与两条数据流，`Run` 负责转发，`RunWithRetryNotify` 负责退避重连并回报每次尝试 |
| `internal/service` | actor 模型：所有改状态的操作经 `cmds` 通道串行执行，状态快照单独加锁，只读查询永不阻塞 |
| `internal/ipc` | 行协议（有长度上限与读写超时）。端点不对对端做凭据校验、也不设连接数上限：能连上它的进程本来就有同等读取能力，权限由文件系统与命名管道 DACL 保证（见 §5.3） |
| `internal/wireguard` | `tun.Device` 实现：按 IPv4 总长度分帧，按需改写地址 |
| `internal/vpntest` | 测试替身：脚本化 portal 与内存隧道服务端 |

### 3.2 几条硬规则（改动时不要破坏）

1. **协议层不许 panic**：所有从服务端响应取值的地方走 `requireTag` / `tagValue`，长度不足返回 `*ProtocolError`。曾经有四处 `FindSubmatch(...)[1]`、一处 `HandshakeState.ServerHello.SessionId`、一处 `(*[48]byte)([]byte(token+twfID))`，每一个都能一次带走整个进程。
2. **失败路径也要交出会话**：`Connect` 在部分失败时返回非 nil 的 `*Session`，调用方必须 `Close`，否则服务端名额不会释放。
3. **一切 I/O 可取消**：`Connect`、隧道重连、登出、IPC 调用都有 ctx 或超时。
4. **连接所有权唯一**：连接由 `Session` 持有并统一关闭；`openStream` / `queryIP` 的每条错误路径都先关连接。曾经 query-ip 失败返回 `(nil, nil, err)`，调用方的清理代码永远是死代码。
5. **状态只能由 actor 改**：隧道协程的退出报告带代次（gen），过期代次一律忽略，否则旧协程会把刚建立的新会话拆掉。

### 3.3 回归测试

`go test ./... -race` 不连任何真实服务端：假 portal 是注入的 `RoundTripper`，假隧道是注入的 `net.Pipe`，都在 `internal/vpntest` 里。覆盖的回归点：畸形响应不 panic、SessionId 过短不越界、复用会话时验证码确实提交、部分失败仍能登出、并发 Close 只登出一次、退避能响应 ctx 取消、流断开后另一条也收敛、Close 不被长 I/O 阻塞、panic 不带走进程、IPC 超长行、配置权限收紧、客户端没接进来时不再有握手噪声。

## 4. 承载层（WireGuard）

承载层用的是用户态 wireguard-go，**不创建 TUN 网卡、不需要 root**：

    Clash Verge / sing-box（客户端，自带用户态网络栈）
      ↕ WireGuard UDP（默认 51820）
    wireguard-go Device（本进程）
      ↕ internal/wireguard.Relay：内存里的 tun.Device，按 IPv4 总长度分帧
      ↕ internal/wireguard.Mapper：peer 地址 ↔ 校园网分配的地址，含校验和增量修正
      ↕ 校园网隧道（TLS 上的私有协议）

- **设备与会话是两条生命周期**：承载设备在服务进程启动时就建好（端口当场占住、私钥与接入公钥当场解析），一次校园网会话只是往它上面挂一个 peer：`SetSession`（隧道端点 + 地址映射）加 `SetPeer`（接入公钥 + peer 地址），断开时两个都摘掉。好处是「端口被占」「密钥写错」这类错误在启动时就暴露，不会白烧一条短信与一次建隧道配额。
- **空闲时不挂 peer**：设备一直监听，但没建立隧道时 peer 是摘掉的。留着它会让客户端握手成功、随后每个包都撞上「没有会话」被丢掉——从客户端看是「连上了但什么都打不开」，比干脆连不上难查得多。
- **客户端没露面时下行包先扣下**：配好 peer、客户端还没握手时，校园网网关自己就会往分配到的地址发包。这些包以前会交给 wireguard-go，而它不知道客户端在哪儿，于是每 5 秒往日志里写一行 `no known endpoint for peer`（真机上 57 秒刷了 12 行）。现在这类包在 Relay 里就被丢掉并按原因计数（第一次一条日志，之后每 5 分钟报一次数）。判据是「收到过客户端解出来的数据包」，而不是回读 UAPI 问 peer 地址：`Read` 跑在 wireguard-go 的 TUN 读取协程里，在那里调 `IpcGet` 会和它的状态机抢 `ipcMutex`，实测能把设备锁死（`Close` 永远等不到读取协程退出）。
- **上行/下行回调是原子替换的**：`TunnelEndpoint` 用 `atomic.Pointer` 而不是读写锁。回调会往长连接里写数据、可能被对端背压挡住，持锁调用就等于要求「注销回调」也必须等它写完——早期实现因此能在 stop 时永久卡住（命令不返回、登出发不出去，只能强杀进程）。回归测试见 `internal/vpn/endpoint_test.go`。
- 私钥留空时首次启动自动生成、按 RFC 7748 夹紧，并**就地写回配置文件**（只替换 `private_key` 那一行，注释与其它字段原样保留）。启动日志会打印服务端公钥，客户端配置要用它。
- UAPI 里的密钥是**十六进制**，配置文件里是 **base64**，两者不能混。
- 客户端 outbound 需要服务端公钥、peer 地址（默认 10.66.66.2）与 `allowed_ips: 0.0.0.0/0`，否则默认路由不进隧道；`ip` 必须与服务端的 `peer_address` 一致。
- 只想让部分目标走隧道时，用 `ip route replace <目标>/32 dev <接口>` 这类前缀路由即可，不必动默认路由：2026-09-12 在校外服务器上就是这么测的，全程没断 SSH。
- **客户端与服务进程必须在同一台机器/同一网络命名空间**：WireGuard 只走 UDP，而某些虚拟机网络模式（例如 WSL 的 VirtioProxy）不让宿主往 guest 的回环地址发 UDP。原生 Ubuntu 上没有这个问题。
- 从校园网里到不了这台机器时（比如笔记本与台式机不在同一网段），UDP 得另找通路：让它走已有的 SOCKS/HTTP 隧道转发 UDP，或用 `socat` / `udp2raw` 之类的工具把 UDP 映射到一条已打通的 TCP 通道上。目前实现里 `wireguard.listen_port` 只在本机监听，没有走代理。
- **与旧实现的差异**：旧仓库自带 SOCKS5 服务与 gvisor 用户态网络栈，本实现两者都不迁移——承载改用 WireGuard，网络栈交给客户端，因此依赖里没有 gvisor。协议层从旧仓库迁移并重写。

验证方式：`internal/wireguard/loopback_test.go` 用一台真实的 wireguard-go 设备（客户端）+ 内存 TUN 做回环，覆盖握手、加密、双向包转发、地址改写、未授权客户端被拒、Close 后停止转发，以及「客户端没接进来时不再有握手噪声」。不需要网卡也不需要 root。

### 4.1 UDP 监听范围（默认只监听回环）

同机方案下服务端与客户端在同一台机器上，没有理由把隧道端口暴露给整个局域网。wireguard-go 自带的绑定用的是 `":port"`（即 0.0.0.0:port），所以 `internal/wireguard/bind.go` 里自己实现了一个最小 `conn.Bind`：

- 只 `ListenUDP` 在 `127.0.0.1`，批量大小固定 1，不用 GSO/PKTINFO/SO_MARK
- 端点直接复用上游的 `conn.StdNetEndpoint`，行为一致
- 关闭后接收函数返回 `net.ErrClosed`，设备的接收协程能正常退出

配置项 `wireguard.listen_host`：`loopback`（默认，也接受 `local` / `127.0.0.1`）只绑回环；`all`（也接受 `any` / `0.0.0.0`）绑全部网卡，需要其他机器接入时用。拼错的值会被拒绝，不会静默放开监听范围（因为依赖方向的原因，配置包里重复了一份取值集合）。

验证方式不是发包探测，而是「能不能在同一个端口的另一个地址上再绑一次」：绑到 0.0.0.0 时再绑具体地址会 EADDRINUSE，只绑回环时绑其他本机地址仍然成功。`bind_test.go` 里既有绑定层的用例，也有设备层的用例（`TestDeviceBindsOnlyLoopbackByDefault`），确保设备真的用了这个绑定。

## 5. 进程模型与路径

### 5.1 平台与进程模型

Windows 与 Linux 都要能用——Linux 侧不是「只用来跑测试」，用 Ubuntu 做主力机的人应该能直接部署。

- `njuvpn start` 先探活，连不上就以脱离终端的方式拉起 `njuvpn run`（记日志到配置同目录），再轮询到就绪。**只影响 start / restart**：stop / status / wg-* 不会拉起服务进程。
- `start` 与 `stop` 幂等：隧道已经在跑时 start 报成功，没在跑时 stop 也报成功（文案与真断开分开）；脚本可以放心按看门狗的方式反复敲。参数错、正在退出、内部错误仍然是失败。
- `njuvpn restart` = 请服务进程收尾退出（含登出）→ 等端点不再响应 → 重新拉起。改完配置用它，不要手工杀进程（手工杀会跳过登出，服务端名额要等超时才释放）。
- 服务进程的退出有两条路径：系统信号（Ctrl-C / systemd / 任务计划程序）与 IPC 的 `shutdown`。两条都走到同一个 `RunServer` 返回处，由 `cmdRun` 的 `defer svc.Close()` 完成登出。
- 开机自启按需另配：Windows 用任务计划程序「登录时启动」；Linux 手写 systemd user unit（`~/.config/systemd/user/njuvpn.service`，要免登录也运行再加 `loginctl enable-linger`）。
- **不做系统服务安装**：服务进程不需要任何特权，装成系统服务反而会落到特权账号上（配置与命名管道的权限都会变成问题），也只在你要用的时候才有存在意义。

#### SSH 登出与无头服务器（2026-09-12 在 Ubuntu 22.04 上实测）

- **SSH 会话结束不会带走服务进程**：CLI 用 `setsid` 让服务进程自成会话（PPID 变成 1）。实测三档都成立——命令跑完连接断开、`ssh -tt` 的客户端被 `kill -9`、以及 `loginctl terminate-session` 强制结束启动它的那个会话，之后进程仍在跑、隧道照常、新会话的命令能正常连上。
- **机制**是 systemd 的 `KillUserProcesses=no`（Ubuntu 默认）：会话结束时那个 scope 变成 `active (abandoned)`，里面的进程不被杀。
- **无头服务器要注意两点**：① 若管理员把 `KillUserProcesses` 设成 `yes`，会话结束会给 scope 内全部进程发 SIGTERM，服务进程会跟着退出（它会先登出，不会留下占名额的残留会话）；② 被 CLI 拉起时进程落在**会话 scope**（`session-*.scope`）里，不在用户管理器下，所以没有守护——崩了不会自动重启。
- 这两种情况的通用做法都是 `loginctl enable-linger <用户>`（需要 sudo）再把服务进程交给 systemd 用户单元或 `systemd-run --user` 跑：那样它落在 `user@<uid>.service` 下，与登录会话无关，也能开机自启（cgroup 位置实测确认）。

### 5.2 路径

- 配置文件：Windows 用 `%LOCALAPPDATA%` 下的 njuvpn 目录，Linux 用 `~/.config/njuvpn/config.yaml`。
- IPC 端点：按配置文件的路径派生（`ipc.EndpointFor`）。Linux 是 `$XDG_RUNTIME_DIR/njuvpn-<实例标识>.sock`（取不到时回落到该用户的私有临时目录），Windows 是 `\\.\pipe\njuvpn-<实例标识>`。同一份配置永远得到同一个端点，不同配置互不相干，多实例因此不会误伤彼此。
- 服务日志：配置文件同目录，名字是 `njuvpn-<实例标识>-<配置名>.log`（光按配置名区分不开 a b.yaml 与 a_b.yaml 这类同名文件）。被拉起的服务进程没有控制台，日志必须有地方去；放在配置旁边的好处是「启动失败」时用户知道该看哪个文件。

### 5.3 安全取舍

威胁模型是「一个人用的个人电脑」，据此分两类。

**不做（无意义或只是自欺）**：

- 防 root：root 能读进程内存、也能读终端输入，写这种防护只是给自己加复杂度。
- IPC 对端凭据校验与连接数上限：能连上这个端点的进程本来就有同等的读取能力，端点该靠权限挡，不该靠协议挡。

**做，但定位是「提高门槛」，不是隔离边界**：同机的其他普通用户是真实存在的（多人共用的机器、多用户 Linux），凭据不该默认摊开。

- 配置文件在加载时收紧到 0600 并提示（原来的 0644 会顺手进备份、进打包给别人排查的压缩包、进镜像快照）。
- 口令可以完全不落盘：`njuvpn start` 从终端读（不回显），经本地套接字交给服务进程，只留在内存里。
- 代理地址经本地套接字下发，不进命令行（`/proc/<pid>/cmdline` 人人可读）。
- IPC 端点放在用户私有目录：Linux 下是 `$XDG_RUNTIME_DIR`，回退路径会校验属主与权限（防止别人抢先建目录、在里面放自己的套接字），套接字本身 0600；Windows 下是显式指定了 DACL 的命名管道，只有当前用户与管理员可访问。

这些挡不住有决心的攻击者，只是不让凭据「一行命令就能读到」。

TLS 全程 `InsecureSkipVerify`：服务端是自签证书、ClientHello 还是刻意畸形的，口令的保密性等价于「没有主动中间人」。要改就是换协议，不是加一行校验。

## 6. 已知坑

- **服务端单客户端**：`Is_enable_mult_client` 为 0，同一账号同时只能有一个隧道会话，且会话按源 IP 索引（登录与建隧道必须同源）。异常退出会留下占名额的会话——这正是「退出时无条件登出」的由来。也意味着**校园网内直连即可，不要走代理**。
- **登出**：`GET /por/logout.csp` 需携带有效 TWFID。`Stop` 与 `fail` 都会先登出再释放资源；服务进程还会在**退出时无条件登出**（相当于 atexit）。隧道与命令处理都在 actor 协程里运行，panic 由该协程的 recover 兜住并收敛成一次失败（不会再带走进程）。登出请求带 10 秒超时，避免网络不通时卡住进程退出。
- **Go 的 nil 接口**：`QueryIp` 失败返回 nil 的 `*tls.UConn`，赋给 `net.Conn` 会得到非 nil 接口，`Close()` 会崩。已修，勿回退。
- **服务端并发限制**：同一 TWFID 短时间反复建连会被拒，重试越密越失败。退避策略是 3 次 × 30 秒。
- **日志**：不得打印密码、密文、TWFID 明文（已有 `redact`，勿回退）。

## 7. 硬性约束

- **仓库内不得出现厂商与产品字眼**（含 git 历史）。提交前遍历全部历史自检：用 `git rev-list --all` 取所有提交，对每个提交跑 `git grep` 匹配词表。词表由用户单独维护，不在仓库内保存。
- **旧仓库 `NJUConnect` 只读**。
- **凭据不入库**。`config.yaml` 已在 `.gitignore`，权限 600。

## 8. 参考实现（协议对照）

1. **sunnysab/smelly-connect**（Rust）— 含 `smelly-tls`，从零实现的 TLS 1.1 客户端。
2. **Yan233th/SHIEP-Pipeline**（Rust）— 含完整控制码表与流握手逻辑。

两者报文格式与本项目逐字节一致，可作为协议对照。注意：这两个项目含本仓库禁止出现的字眼，只作只读参考，不要带任何字眼或代码片段进来。

## 9. 开发与排查

### 9.1 真实服务端实验

`internal/vpn/live_*.go` 里的用例默认跳过（跑一次会消耗账号配额，有的还发短信），要用环境变量显式打开：

| 变量 | 作用 |
|---|---|
| `NJUVPN_LIVE_CONFIG` | 真实账号的配置文件路径；不设置就跳过所有 live 用例 |
| `NJUVPN_LIVE_CONNECT=1` | 允许跑完整登录（会发短信） |
| `NJUVPN_LIVE_CODE` | 直接给出验证码，省掉 stdin 交互 |
| `NJUVPN_LIVE_WAIT` | 短信诊断用例的等待秒数 |

    export NJUVPN_LIVE_CONFIG=/tmp/njuvpn-lab.yaml
    go test ./internal/vpn/ -run TestLiveLoginPage -v     # 免费：只取登录页
    NJUVPN_LIVE_CONNECT=1 go test ./internal/vpn/ -run TestLiveConnect -v   # 花一条短信

阶梯的意义在于每一步都能单独定位故障：login-page 验证真实 TLS + HTTP + 页面解析；connect 走口令登录 → 二次验证 → token → query-ip → 流握手。连不上时先确认前一级通过，再往后查。

### 9.2 检查清单与工具基线

提交前跑 `scripts/check.sh`（CI 用同一个脚本）：`gofmt -l .`、`go vet ./...`、`go test ./... -race`、`staticcheck ./...`——四者都应当无输出/全绿。`scripts/build-release.sh <版本>` 生成各平台产物（产物目录不进 git）。

其余工具的输出有已知基线，基线之外的新条目才需要看：

- `govulncheck ./...`：0 命中（依赖模块里有若干，但代码没调用）。
- `gosec`：63 条（2026-09-12 实测），全部是设计使然——G104 ×50（没检查错误返回，多数是 `defer Close` 与写日志）、G115 ×5（端口/长度的整数转换，别处已校验）、G304 ×4（配置路径来自用户输入，本来就该读）、G204 ×1（拉起服务进程是设计的一部分）、G302 ×1 与 G703 ×1（日志与配置文件权限）、G402 ×1（不校验证书，见 §5.3）。
- `deadcode`：命中 `internal/vpntest` 全包（测试替身）与 `Service.SetDialer` / `Service.SetClientOptions`（生产类型上的测试注入点）。这两类是有意保留的，但**不要在这条路上再加第三个注入点**：真要加，先讨论把它改成构造参数。

### 9.3 调试时踩过的坑

1. **`Get-CimInstance Win32_Process` 的 Read/WriteTransferCount 不是网络流量**，是进程的文件 I/O 计数。用它判断「隧道有没有搬包」会得到完全错误的结论。要判断承载层是否在工作，用 mihomo 的 API 做延迟测试，或看 `njuvpn wg-stats`。
2. **不要用 grep Clash 的配置文件来判断节点是否存在**：Clash Verge 的运行配置由 GUI 重新生成，位置和时机都不受我们控制。要查就查 mihomo 的 API（`/proxies`），那才是运行时的事实。
3. **`ip route get` 会告诉你内核实际选了哪条路由**。测隧道时如果只加了 /32 路由，别忘了那条路由的目标地址才是触发握手的流量。

### 9.4 看着像坑、其实是设计（别改）

- 自己实现 `loopbackBind`、手写 SOCKS5 握手：为「不建网卡、不要特权」服务，不是重新发明轮子。
- `persistWireGuardField` 手写 YAML 行编辑：为保留用户手写的注释，换成 yaml 序列化会把注释全丢掉。
- 中文子串分类（「频繁」「过期」「未登录」）：服务端返回的就是中文 XML，协议给不出更结构化的判据。
- 服务端 RSA 公钥只按 1024 位下限校验：防的是明显不对的公钥，不是中间人。
- 仓库根的 `config.yaml` 存在、0600、被 ignore：那是使用者的真实配置，不是要清理的垃圾。
- 发行产物目录不进 git：需要时用 `scripts/build-release.sh` 重新生成。

暂不做：428 的独立退出码、TLS pinning、配置文件权限过宽时拒绝启动（现在是收紧并提示）、IPC 对端校验与连接数上限、防 root（同机其他用户那一层的门槛见 §5.3）。

### 9.5 已知的复杂度尖峰

`internal/service/server.go` 的 `dispatch`（约 150 行，11 个命令各有一套错误到状态码的映射）与 `cmd/njuvpn/main.go` 的 `cmdProbe`（约 150 行、8 个 flag）都不要继续在上面加：下一个新命令或新 flag 落地前先按命令族拆开。

## 10. 待办

进行中：

- [ ] macOS 实测（产物目前只保证能编译）
- [ ] 客户端接入的其他网络组合（已验证的是同机 Clash 出站与同机内核客户端）

不打算做（做法记在 §5.1）：

- 开机自启内置到程序里

已完成：

- [x] 端到端联调：服务进程 → 隧道 up → Clash Verge 接入
- [x] 校外 Ubuntu 上的服务进程侧与内核客户端接入
- [x] WireGuard 私钥首次启动自动生成并写回配置
- [x] 协议层与服务层的健壮性重构（见 §3.2）
- [x] 三轮逐条代码审查的收口：协议边界与错误路径、死锁链、短读、状态码分级、stop 打断、凭据脱敏、握手噪声——每轮都带回归测试
- [x] 配置文件权限在加载时收紧到 0600 并提示
- [x] 文档分工整理：README 管「怎么用」，本文管「为什么」
- [x] 检查脚本与 CI
