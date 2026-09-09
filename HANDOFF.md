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

## 4. 建议的下一步（笔记本上）

按信息量排序：

1. **先在手机热点下验证本客户端**。
   把仓库拷到笔记本，笔记本连手机热点（不要连校园网），跑：

       go run ./cmd/njuvpn probe -config config.yaml

   如果 query-ip 通过，就确认是「校园网来源 IP 被拒」，本项目的协议实现没有问题，
   后续只需把部署场景限定在校外使用。这一步成本最低、信息量最大。

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
