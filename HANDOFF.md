# 交接文档

本文档面向在另一台机器（笔记本电脑 WSL）上接手本项目的会话。
请先完整读一遍，再动手。仓库内的 NOTES.md 是历史记录，本文档是当前状态的入口。

## 1. 项目目标

把 NJU VPN 客户端重新实现一遍。旧仓库 NJUConnect 是只读参考，
不修改、不复制其厂商与产品相关字眼。

最终形态是**一个二进制、三个角色**：

    njuvpn run                        服务进程，由 systemd / Windows SCM 拉起
    njuvpn start|stop|status|auth     命令行客户端，通过本地 IPC 与服务进程通信
    njuvpn service install|...        安装、卸载、控制操作系统服务
    njuvpn probe                      协议探测（开发用，不建立数据通路）

承载层选 WireGuard（wireguard-go）：服务进程不需要 root、不建 TUN 网卡，
客户端（sing-box / Clash.Meta 等）用自带的用户态网络栈接入。

## 2. 当前进度

| 模块 | 状态 | 说明 |
|---|---|---|
| internal/vpn（协议层） | 完成 | 登录、短信/TOTP、portal token、uTLS 隧道 |
| internal/config | 完成 | yaml 读取、默认值、校验 |
| internal/dial | 完成 | 直连 / HTTP CONNECT / SOCKS5，全部出站走同一个拨号器 |
| internal/ipc | 完成 | Linux unix socket（0600）/ Windows 命名管道 + 行协议 |
| internal/wireguard | 完成 | Relay 实现 tun.Device；Mapper 做 SNAT/DNAT 并增量修校验和 |
| internal/service | 完成 | 状态机 + 隧道生命周期 + IPC 服务端 + 服务安装 |
| cmd/njuvpn | 完成 | run/start/stop/status/auth/probe/service 全部接通 |
| **端到端联调** | **阻塞** | 隧道建立被服务端拒绝，见第 3 节 |

代码规模约 3300 行。go build、go vet、go test 全部通过，Linux 与 Windows 交叉编译通过。
测试覆盖：地址映射的校验和（internal/wireguard）、短信与登出状态分类（internal/vpn）。

## 3. 阻塞点：服务端拒绝建立隧道

### 3.1 现象

登录全流程正常，只有建隧道失败：

| 阶段 | 结果 |
|---|---|
| web-login | 一直 OK |
| auth-sms | OK（验证码正确时） |
| portal-token | 一直 OK |
| **query-ip** | **被拒**，收到固定 36 字节 |
| **tunnel-handshake** | **被拒**，同样内容 |

服务端返回的 36 字节（不同账号、不同 TWFID 完全一致）：

    030000000000000000c5100285562bdb a0e3b788fe7f0000 170c83a2867f0000 e0e3b788

偏移 16、28 处的 0x00007ffe... 与 0x00007f86... 是典型的 x86-64 用户空间指针
（栈 / 堆映射区），整段形如服务端进程的内存内容，不是协议响应。

### 3.2 关键对照事实

- **官方客户端在同一台笔记本（手机热点、校外 IP）上能成功建隧道**，用的还是旧账号。
  这条最重要：它排除了「服务端故障」和「账号异常」。
- 唯一一次成功记录：2026-09-09 23:32，本客户端完整走完四个阶段，分配 172.29.56.18。
  之后所有尝试都失败，且成功与否看起来是随机的（连续失败若干次后偶然成功过两次）。

### 3.3 已经排除的假设（都有实验证据，不要重复验证）

| 假设 | 排除依据 |
|---|---|
| uTLS 版本问题 | v1.2.0 与 v1.8.2 表现一致；两个版本构造的 ClientHello 字节完全相同 |
| TwfID 过期 | 全新登录拿到的 TWFID 同样失败 |
| 账号级限制 | 换第二个账号，返回的 36 字节逐字节相同 |
| 源 IP 跳变 | 代理出口固定为单一 IP（10/10 次一致）时仍失败 |
| 代理路径 | 校园网内直连服务端 IP（10ms）同样失败 |
| 多客户端占用 | 关掉官方客户端后仍失败（登录响应里 Is_enable_mult_client 为 0） |
| 报文格式错误 | 9 种 opcode（0x00..0x08，含合法的 0x00/0x05/0x06）返回完全相同的 36 字节；
| | 伪造 TWFID（全 0）与真实 TWFID 也返回相同内容 |
| 服务端整体故障 | 官方客户端能成功 |

### 3.4 当前最可疑的方向

1. **网络路径差异**。官方客户端成功那次走的是手机热点（校外 IP）；
   本机是校园网有线（校园网内网段/21）。服务端可能只对校外来源开放隧道建立。
2. **TLS 层的真实差异**。ClientHello 字节一致，但握手之后的数据流行为可能不同，
   服务端可能因此把连接判成非法客户端。需要抓包对比官方客户端。
3. **协议细节差异**。官方客户端可能在建隧道前多做了一步我们没做的事
   （例如某个初始化请求、或者不同的流建立顺序）。

### 3.5 重大修正：那 36 字节是控制帧，不是内存垃圾（2026-09-10）

找到两个独立实现后（见第 10 节），结论要改写：

**36 字节是「命令回复体」：4 字节小端控制码 + 32 字节不透明数据。**
偏移 16、28 处的值确实是内存地址，那是服务端填帧时的遗留内容，
但**开头的 4 字节是有意义的控制码**，不是随机数据。

控制码表（来自 Yan233th/SHIEP-Pipeline 的 protocol_wire.rs）：

| 码 | 名称 | 含义 |
|---|---|---|
| 0 | SendIp | 成功，后面跟分配到的 IP |
| 1 | RxAck | 下行流握手回执 |
| 2 | TxAck | 上行流握手回执 |
| 3 | ServerReset | 服务端重置了会话 |
| 4 | Recovered | 会话已恢复 |
| 5 | IpBusy | 地址被占用 |
| 8 | Shutdown | 服务端要求断开 |
| 9 | IpConflict | 地址冲突 |
| 14 | IpKick | 被踢下线 |
| 15 | Heartbeat | 心跳 |

实测对应关系：

- **假 token → 08（Shutdown）**，恒定；
- **真实 token → 03（ServerReset）**，或偶发 08。

也就是说服务端确实解析了我们的 token，并给出「会话被重置」的回复。

服务端路由行为（实测，无需凭据）：

| 连接形态 | 结果 |
|---|---|
| SessionId 以 L3IP 开头 + 发 query-ip | 36 字节控制帧 |
| SessionId 以 L3IP 开头 + 不发数据 | 服务端静默等待，读超时 |
| SessionId 不以 L3IP 开头 | **TLS 握手直接失败** |

这证明 TLS 层与 L3IP 识别都是对的，问题出在会话状态上。

**关于「残留会话占位」这一假设：已被排除。**
登录响应里 `Is_enable_mult_client` 为 0（同一账号只允许一个客户端），
一度据此怀疑是本项目反复探测积累的残留会话。但用户确认：
**第二个账号从未成功建立过任何会话，同样失败**。
而且第二个账号测试时走的是固定日本节点（单一出口 IP）与校园网直连
（单一出口 IP）两条路径，都失败。所以既不是残留会话，也不是源 IP 跳变。

**当前最合理的假设：隧道会话按源 IP 索引，共享源 IP 会互相冲突。**

- 校园网是 NAT 出口，一个公网 IP 后面有大量用户；
- 代理的出口 IP 同样被众多用户共享；
- 官方客户端成功那次，手机热点给的是独占 IP。

若服务端用源 IP 作为隧道会话的键，那么从共享 IP 发起时很可能撞上
他人已有的会话，于是返回 ServerReset(3)。这同时解释了账户 1 在
23:32 偶尔成功——香港集群的 IP 池里恰好有当时的空闲 IP。

**因此最干净的验证是：在与官方客户端成功时相同的环境下跑本客户端。**
也就是笔记本 + 手机热点，用**第一个账号**（官方客户端曾在同一账号成功），
不要用第二个账号——保持账号变量不变，只换实现。
若本客户端在该环境下也成功，则确认问题是「源 IP 被占用 / 校园网来源」；
若失败，则问题在本实现，需按第 10 节对照参考实现逐项排查。

**ClientHello 差异（供参考，实测不影响假 token 的响应）**：
两个参考实现都用「压缩方法 [1,0]」并带心跳扩展（0x000f，长度 1，数据 1）；
本项目当前是「压缩方法 [0]、无任何扩展」。实测四种组合对假 token 的
响应完全相同，所以不是当前故障的直接原因，但若后续需要对齐官方客户端，
这是已知差异。uTLS 里可用 `&tls.GenericExtension{Id: 0x000f, Data: []byte{1}}` 构造。

另注：尝试用 TLS 1.2 握手会被服务端强制降到 TLS 1.1
（uTLS 报 `server selected unsupported protocol version 302`），
说明隧道通道固定为 TLS 1.1，与参考实现一致。

## 4. 建议的下一步（笔记本上）

按信息量排序：

1. **先在手机热点下验证本客户端**。
   把仓库拷到笔记本，笔记本连手机热点（不要连校园网）。
   用**第一个账号**——官方客户端曾在同一账号 + 同一环境下成功，
   这样只改变「实现」这一个变量。用户只有两个账号，都已被本项目用过，
   所以无法用「全新账号」做对照，请勿再假设有新账号可用。跑：

       go run ./cmd/njuvpn probe -config config.yaml

   如果 query-ip 通过，就确认是「校园网来源 IP 被拒」，本项目的协议实现没有问题，
   后续只需把部署场景限定在校外使用。这一步成本最低、信息量最大。

   若失败，先看返回的控制码：03 表示会话被重置、08 表示被要求断开、
   05 表示地址被占用。这几个码的含义见 3.5 节。

   若本客户端在热点下也失败，**立刻用官方客户端在同一账号同一环境再跑一次**，
   确认环境仍然可用，以此区分「实现问题」与「账号/环境问题」。

2. **用容器化的官方客户端做对照抓包**。
   笔记本 WSL 里已部署该容器化方案（用户自己搭的）。让它在同样的网络下建立隧道，
   同时用 tcpdump 抓 443 端口流量，与本客户端的流量对比。重点看：

   - TLS 握手的 record 分片与填充是否不同；
   - 建隧道前是否还有我们没发的请求；
   - query-ip 的报文之后，官方客户端收到了什么。

   注意：官方客户端与服务端之间的流量是 TLS 加密的，除非配置了 HTTPS 中间人，
   否则只能看到长度与时序。必要时用 WSL 的 HTTPS 抓包环境（用户可自行配置）。

3. **如果热点下也失败**，则回到协议层：
   用官方客户端的版本号与服务端 M7.6.8R2 做兼容性核对，
   并检查旧仓库的 dev 分支与各 fork 是否有未合并的协议修复。

## 5. 硬性约束

- **仓库内不得出现厂商与产品字眼**（大小写均不可，包括 git 历史）。
  当前已确认全历史干净。新增代码与文档务必遵守。
  提交前遍历全部历史自检（无输出即干净）：用 git rev-list --all 取出所有提交，
  对每个提交跑 git grep，匹配厂商名与产品名（含官方客户端名与中间件名）。
  具体词表由用户单独维护，不在本仓库内保存，也不要写出这些字眼。
- **旧仓库 NJUConnect 只读**，不修改。
- **凭据不落盘到仓库**。config.yaml 已在 .gitignore 中，权限 600。
- 日志不得打印密码、密文、TWFID 明文（已有 redact 处理，勿回退）。

## 6. 迁移步骤

1. 只拷 git 仓库即可，不要连带工作区里的敏感文件：

       git clone <仓库目录> 目标目录

   或者直接打包仓库目录但**排除 config.yaml**（含账号密码）。
   确认目标机器上没有 njuvpn/config.yaml 的副本。

2. Go 环境：本机用 go1.26.0（/usr/bin/go）。模块代理已全局配置：

       go env -w GOPROXY=https://goproxy.cn,direct
       go env -w GOSUMDB=sum.golang.google.cn

   新机器上需要重新设置（默认的 proxy.golang.org 在本网络下会失败）。

3. 重新写一份 config.yaml（参考 config.example.yaml），填入测试账号。
   IPC 端点在校内测试时用 /tmp 下的路径，/run/njuvpn.sock 需要 root。

4. 代理：本机的 Clash 走 127.0.0.1:7897。注意订阅里的「香港集群」等 mieru 节点
   出口 IP 会在多个地址间跳变（服务商负载均衡），需要选固定出口的 hy2 节点。
   若在手机热点下测试，则**不要**配 proxy，直接直连。

## 7. 技术要点备忘

### 7.1 协议层关键细节

- 隧道用 uTLS 构造刻意畸形的 ClientHello：TLS 1.1、RC4-SHA 套件、
  SessionId 以 L3IP 开头。缺任何一项服务端都会拒握手。
- 服务端 443 端口同时承载 Web 登录和隧道，靠 ClientHello 特征区分。
- PortalToken 的实现依赖：用有效 TWFID 发 HTTPS 请求后，
  ServerHello 的 SessionId 前 31 字节即 token 前半段（拼接 0x00 与 16 字节 TWFID 得 48 字节）。
  注意 rclist.csp 不校验 TWFID，conf.csp 才校验——不要用它来判断 TWFID 是否有效。
- query-ip 建立的连接**必须保持打开**到隧道握手完成，否则服务端会断开 i/o 流。

### 7.2 已知坑

- **短信状态语义**：服务端响应的 IS_IN_PERIOD=1、SmsSendInterval、
  以及 CompatData 里的 g_DisableTime，都是「本次发送之后前端按钮的禁用倒计时」，
  **不是**「没有重发」。ErrorCode=1 且带 USER_PHONE 即表示已发送。
  这一条曾经解读反了，导致每次实际发出的短信都被误报成「未重发」。
- **Go 的 nil 接口陷阱**：QueryIp 失败时返回 nil 的 *tls.UConn，
  若直接赋给 net.Conn 会得到非 nil 接口，Close() 会崩。已修，勿回退。
- **服务端并发限制**：同一 TWFID 短时间内反复建连会持续被拒，
  重试越密集越失败。probe 里只保留 3 次 × 30 秒的退避。
- **登出**：GET /por/logout.csp 携带有效 TWFID 才生效。
  Service.Stop 与 fail 都会先登出再释放本地资源，避免服务端残留会话。

### 7.3 命令速查

    # 协议探测（可用 -twf-id 复用会话，跳过短信）
    go run ./cmd/njuvpn probe -config config.yaml [-twf-id <id>] [-debug]

    # 只登出某个会话
    go run ./cmd/njuvpn probe -config config.yaml -logout -twf-id <id>

    # 服务进程 + 命令行客户端
    go run ./cmd/njuvpn run -config config.yaml &
    go run ./cmd/njuvpn start -config config.yaml
    go run ./cmd/njuvpn auth <code> -config config.yaml
    go run ./cmd/njuvpn status -config config.yaml
    go run ./cmd/njuvpn stop -config config.yaml

### 7.4 测试账号的注意事项

测试账号需要短信验证码，每次 start 会真的发一条短信。
验证时尽量复用 TWFID（-twf-id）而不是重新登录，可以省掉短信。
注意服务端有约 180 秒的发送冷却。

### 7.5 抓包与 MITM 的可行性（实测结论）

隧道连接实际协商的 TLS 参数（实测，在校园网内直连服务端）：

    版本 = 0x0302 (TLS 1.1)
    套件 = 0x0005 (TLS_RSA_WITH_RC4_128_SHA)

**标准 MITM 工具（mitmproxy / Charles / Fiddler 之类）在本场景不可用**，
有两个相互独立的原因：

1. 它们依赖 OpenSSL 或 Python 的 ssl 模块，而现代 OpenSSL 3.x 已移除
   RC4 与 TLS 1.1。实测 `openssl ciphers -v 'RC4'` 与 `openssl ciphers -v 'TLSv1.1'`
   都报 `no cipher match`。这些工具根本无法与上游协商出服务端要求的套件。
2. MITM 必须终止客户端的 TLS，再以自己的身份向上游重新发起 TLS。
   服务端在同一 443 端口上靠 ClientHello 特征区分隧道流量与 Web 流量，
   上游看到的是代理的 ClientHello，隧道握手必然失败。

注意服务端**接受**标准 TLS 1.2（实测协商出 ECDHE-RSA-AES256-GCM-SHA384），
但那走的是 Web 认证通道——PortalToken 用的就是这条。所以普通 MITM 不会报错，
只会把隧道连接悄悄降级成 Web 连接，然后握手失败，很容易误判。

**可用方案**，按可靠性排序：

1. **在容器内用 LD_PRELOAD 挂钩 `SSL_read` / `SSL_write`**（推荐）。
   直接拿到应用层明文，不依赖证书信任，也不受 TLS 版本限制。
   官方 Linux 客户端在容器里跑，注入一个 dump 明文的小 .so 即可。
   需要先确认它链接的是动态 OpenSSL（`ldd` 看一下）。
2. **自写 uTLS 终止代理**。Go 的 uTLS 仍然实现了 RC4-SHA
   （cipher_suites.go 里有 TLS_RSA_WITH_RC4_128_SHA），本仓库的 TLSConn 就是证据。
   用它复现完全相同的 ClientHello 连上游，同时用自签证书面对客户端。
   注意服务端证书是有效的 DigiCert 通配证书，官方客户端可能校验证书，
   必要时把自签 CA 装进容器的信任库。
3. **tcpdump 被动抓包**。只能看到长度与时序，看不到明文，
   但足以对比 ClientHello 形状与 record 分片。

无论用哪种方式，要对比的关键点是：官方客户端在 TLS 握手之后发出的
第一个应用层报文、以及它收到的回应，与本仓库 query-ip 的 64 字节是否一致。

## 8. 代码结构

    cmd/njuvpn/main.go        子命令分发与参数解析
    cmd/njuvpn/client.go      CLI 侧的 IPC 调用
    internal/vpn/             协议层（login/tunnel/logout/probe/totp/endpoint/client）
    internal/dial/            出站拨号（直连/HTTP CONNECT/SOCKS5）
    internal/config/          配置读取与校验
    internal/ipc/             本地通信传输层 + 行协议
    internal/wireguard/       tun.Device 实现与地址映射
    internal/service/         状态机、隧道生命周期、IPC 服务端、系统服务安装

## 9. 首次接手后的建议动作

1. 读本文档与 NOTES.md；
2. go build ./... 与 go test ./... 确认环境正常；
3. 按第 4 节第 1 条，在手机热点下跑一次 probe，判定是否为网络来源问题；
4. 把结论追加到 NOTES.md，再决定后续方向。

## 10. 参考实现（重要资源）

本项目之外还有两个独立实现，都能作为协议对照，比逆向官方客户端便宜得多：

1. **sunnysab/smelly-connect**（Rust）
   含 `smelly-tls`：从零实现的 TLS 1.1 客户端，专门用于本协议的隧道握手。
   关键文件：`smelly-tls/src/lib.rs`（ClientHello 构造）、
   `smelly-connect/src/kernel/tunnel/`（握手报文与 token 派生）。
2. **Yan233th/SHIEP-Pipeline**（Rust）
   含完整控制码表与流握手逻辑。
   关键文件：`crates/ec-core/src/protocol_wire.rs`（报文格式与控制码）、
   `crates/ec-core/src/protocol.rs`（状态机与重试）、
   `crates/ec-core/src/tls.rs`、`crates/ec-core/src/protocol_session.rs`（L3IP 会话伪造）。

两个实现的报文格式与本项目**逐字节一致**（token 48 字节 = 31 字节会话 ID +
`\x00` + 16 字节 TWFID；query-ip 64 字节；流握手 64 字节，末 4 字节为反序 IP）。
这说明本项目的协议层是正确的，不必再去逆向官方客户端。

注意：这两个项目里含有本仓库禁止出现的厂商与产品字眼，
**只作只读参考，不要把任何字眼或代码片段带进本仓库**。
