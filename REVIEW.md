# REVIEW.md — 多实例部署改造清单

> 待办清单，不是文档。核对并改完后应删除，或并入 HANDOFF.md。
> 状态：git 未跟踪，未提交。

## 0. 前提与边界

**目标场景**

- 一台公网服务器上多人共用，每人持有自己的学校账号；每人一个实例：独立进程、独立配置文件、独立 UDP 端口、独立 IPC 端点。
- 不安装系统服务（Windows 与 Linux 一致），进程仍由 `njuvpn start` 按需拉起。
- 个人 Windows 笔记本 / Linux 桌面单机使用是次场景，同一套代码不得退化。

**信任边界（假定）**

 假定运行账户为个人所有：同机其它用户没有该账户的写权限，也不与其共享提权。
 本地防护（配置文件权限、IPC 套接字、Windows 管道 DACL）针对的是同机非特权用户，以及配置文件的意外扩散（备份、快照、贴日志）。
 部署要求：多人共用一台服务器时每人使用独立的系统账户。不满足这条时，上述本地防护只起防误操作作用，不构成隔离边界。

**已定的取舍（不再讨论）**

- 不引入 TUN 网卡、不引入用户态网络栈；客户端侧继续用 WireGuard 出站。
 - CLI 收敛为「一条 `start` 走完全程」（本批次已定，详见 C4、C5）：取消用户可见的 `auth` 子命令，验证码在 `start` 过程中从 stdin 读；配置文件允许不写口令，此时口令同样在 `start` 过程中从 stdin 读，只存在于服务进程内存。
- 不做配置文件加密：挡不住 root，也挡不住运行期读内存，价值可被「盘上无明文」覆盖。
- 加固尺度以「防误操作 + 防意外泄露」为准，不追求对抗性安全。

**审查方式**

三个独立子代理分别从「实例生命周期/状态机/可观测性」「安全/凭据/权限」「共享资源/学校侧协议约束」三个角度审查，关键条目本机复核。`go vet ./...` 无输出，`go test ./...` 与 `go test -race ./...` 全绿。本轮未改动任何文件。

**标注约定**：每条含 位置 / 现状与后果 / 改法 / 工作量（小 ≤ 半天，中 1-2 天，大 > 2 天）/ 是否过度设计。「核实」= 已读代码或跑命令确认，「推断」= 未实测。

---

## 1. 多实例隔离与身份（主场景阻塞项）

### M1 默认 IPC 端点不区分实例，命令会静默打在错误的账号上 —— 高

- 位置：internal/ipc/listen_unix.go:18、internal/ipc/listen_windows.go:16、cmd/njuvpn/service_process.go:75、cmd/njuvpn/client.go:58
- 现状（核实）：同一 uid 下用两份配置各起一个实例时，第二个 `run` 因「已有服务进程在监听」退出；CLI 探活打到的是第一个实例，于是 `njuvpn start -config b.yaml` 会把 A 的账号拉起来并打印「隧道已建立」，`stop` / `status` 同理。Windows 侧默认管道名是常量 `\\.\pipe\njuvpn`，表现为第二个实例起不来（响亮但难懂）。
- 改法：默认端点按配置文件路径派生（如 `njuvpn-<hash8>`）；Linux 的 /tmp 回退目录名一并改掉，消除可预测性。README 增「同机多实例」一节：每实例必须有独立的 config、ipc.endpoint、listen_port、日志目录，且使用独立的系统账户。
- 派生要按**规范化后的配置路径**：`filepath.Abs` → `filepath.EvalSymlinks`（失败时回落 `Abs`，例如文件还不存在）→ Windows 上对哈希输入统一小写。同一个 helper 必须同时被服务进程（internal/service/server.go:268）与 CLI（cmd/njuvpn/client.go:58）调用，规则只留一份；单测覆盖相对路径、`..`、符号链接、文件不存在、Windows 大小写。
- 派生只依赖路径这个「身份」，不依赖文件内容（已否决内容 hash 方案）：改配置后 `restart` 必须仍能找到正在跑的进程，否则会杀掉不成、另起一个，旧进程继续占着学校侧的会话名额。
- 内容 hash 还有两个本仓库特有的坑：服务进程启动时会自动生成私钥并写回配置（cmd/njuvpn/main.go:135，发生在监听之前），`wg-peer` 也会写回客户端公钥（internal/service/service.go:433）——也就是说**程序自己会改文件内容**，端点会因此漂移，第一次启动就中招。另外内容 hash 在配置文件暂时读不出来时算不出端点，而 CLI 的现有设计容忍这种情况（见 M2）。
- 内容 hash 唯一的优势是移动 / 改名配置文件时端点不变，而这个需求由显式 `ipc.endpoint` 覆盖：固定身份应当靠用户写死的路径，而不是靠「文件内容永不变」这个假设。
- 语义上，端点回答的是「我在跟哪个实例说话」，实例身份是「哪份配置文件」而不是「配置里写了什么」：两份尚未编辑过的相同配置应当被当成两个实例（现在是两个、且必然抢同一个端口），内容 hash 会把它们算成一个。
- 残留边界（写进文档）：移动或改名配置文件会换端点，旧进程变成联系不上的孤儿；硬链接与 bind mount 不统一；Windows 的 8.3 短名不统一。`ipc.endpoint` 保持显式覆盖，并在配置校验里拒绝相对路径（相对 socket 路径随 cwd 漂移）。
- 工作量：小。过度设计：否。

### M2 显式 `-config` 加载失败会回落默认端点，可能误伤别的实例 —— 高

- 位置：cmd/njuvpn/client.go:19-30、:58-63、:75
- 现状（核实）：配置读不出来时返回空 Config，端点退化为平台默认；`restart -config b.yaml` 于是变成「杀掉一个健康的 A、拉起 B 失败、退出码 1」，stderr 只有一行警告，脚本里等于看不见。
- 改法：只有未显式给 `-config` 时才允许回落；显式给了却加载失败 → 打印错误并非 0 退出，不发任何命令。
- 工作量：小。过度设计：否。

### M3 会话占用类报错要指路 —— 中

- 位置：internal/ipc/listen_unix.go:81、cmd/njuvpn/service_process.go:87-94
- 现状（核实）：报错只说事实不说怎么办；`restart` 后会干等 10 秒再报「没有就绪」。
- 改法：报错写明「多实例请为每个实例设置不同的 ipc.endpoint，并在 CLI 上带 -config 指向对应配置」；子进程立刻退出时直接打印日志尾部（依赖 R5）。
- 工作量：小。过度设计：否。

### M4 实例身份在日志与 status 中完全不可见 —— 中

- 位置：cmd/njuvpn/service_process.go:35、cmd/njuvpn/main.go:124、internal/service/service.go:558、internal/service/server.go:245
- 现状（核实）：日志文件名固定为配置目录下的 njuvpn.log（同目录多份配置共用一份，O_APPEND 不会撕碎行但会交错）；日志行与 status 输出都不带 PID / 配置路径 / 端点 / 用户名。多实例连同一台学校服务器时日志几乎逐字相同，排查容易张冠李戴。
- 改法：启动打一行身份（PID、配置路径、端点、username，不含任何凭据）；`ping` / `status` 返回同样字段并展示。
- 工作量：小。过度设计：否。

### M5 `XDG_RUNTIME_DIR` 有无会改变端点，同一配置可能被拉起两次 —— 中

- 位置：internal/ipc/listen_unix.go:18
- 现状（核实）：交互登录时端点在 /run/user/<uid>；cron、容器、su 等环境没有该变量，端点落到 /tmp/njuvpn-<uid>/。后者探活打不到前者，于是再拉起一个进程，两个进程用同一账号互相顶掉，用户只看到「被服务端踢下线」。
- 改法：随 M1 的实例派生端点解决；文档要求 Linux 上显式写固定绝对路径的 `ipc.endpoint`。
- 工作量：小（随 M1）。过度设计：否。

---

## 2. 凭据与隐私

### C1 配置文件权限没有保证，按当前文档操作会产出全机可读的凭据 —— 高

- 位置：internal/config/config.go:98-101（Load 注释明确「不检查文件权限」）、:332-345、config.example.yaml、README.md
- 现状（核实）：config.example.yaml 是 0644，本机 umask 0022，README 教「复制一份填写」，产物因此是 0644；文件里同时有校园网口令、TOTP 长期密钥、WireGuard 私钥。真实泄露路径多为意外：rsync 备份、打包发给别人排查、被快照进镜像。
- 改法：Load 时若 group/other 有任何权限位 → 收成 0600（或拒绝启动并说明原因）；样例文件改 0600；README 补一句。
- 工作量：小。过度设计：否。
- 注：定位是「别让它默认摊开」与挡住离线副本，不作为隔离边界（见第 0 节）。C4 落地后配置里仍有 TOTP 密钥与 WireGuard 私钥，这条不能省。

### C2 代理 URL 里的凭据会进日志、status 与错误串 —— 中

- 位置：cmd/njuvpn/main.go:130、:322、internal/dial/dial.go:50 / :56 / :61（同文件 :82 已正确使用 Redacted，属漏改）
- 现状（核实）：`proxy: socks5://user:pass@host:1080` 的原文会被打印，并经 fail() 进入 status 详情。
- 改法：统一走 `url.Parse(...).Redacted()`，或在 config 层提供 ProxyRedacted()。
- 工作量：小。过度设计：否。

### C3 凭据不进日志没有回归测试 —— 中

- 位置：internal/vpn/regression_test.go（现有用例只覆盖 redact 函数本身）
- 现状（核实）：历史上确实出现过明文口令进日志的缺陷（已修复），但没有任何用例会在「有人再加一行 log.Printf(password)」时失败。
- 改法：用假 portal 跑一次登录，抓日志输出，断言不含口令、CSRF 码、密文、TOTP 密钥、TwfID 全文。
- 工作量：小。过度设计：否。

### C4 口令与验证码都改由 `start` 从 stdin 读入（已定）—— 中

- 位置：cmd/njuvpn/main.go:44（usage）、:250-266（cmdAuth）、:359 与 internal/service/service.go:341 / :387（两处读 cfg.Password）、internal/config/config.go:185（validate 要求 password 非空）、internal/ipc/protocol.go、cmd/njuvpn/client.go:97（promptCode 已有先例）。

- 现状（核实）：口令只能写在配置文件里；二次验证要在 `start` 之后再敲一条 `njuvpn auth <code>`，服务进程停在 auth_pending 等它。

- 目标（已定）：少敲一条命令；口令不出现在磁盘上（配置文件、日志、备份）。配置里 `password` 留空即可，口令与验证码都在 `start` 过程中从 stdin 读入，口令只存在于服务进程内存。

- 改法（建议顺序）：

1. `config.validate()` 不再要求 password 非空（否则服务进程读不了这份配置）；`KnownFields` 仍负责挡住键名写错。
2. 服务进程内引入「凭据持有者」：内存中保存 username / password / totp，`cfg.Password` 只作为初始值；`error` 状态恢复、重连后重登都从这里读，行为与现状一致（不必再次输入）。
3. CLI 侧：`start` 先按 `-config` 解析配置，password 为空时从 stdin 读一行，随请求携带。编码建议 base64：IPC 是文本行协议、`strings.Fields` 按空白切分，口令含空格会被切碎；base64 同时避免它原样出现在任何报文转储里。
4. 验证码沿用现有机制：服务端返回 428（CodeAuthRequired），CLI 提示后发同一个 `auth` IPC 命令——删掉的是用户可见的子命令，不是 IPC 命令。
5. `probe` 同样支持从 stdin 读口令（它不经服务进程，直接登录）。
6. stdin 不是终端时读取失败要给出可操作报错（提示需交互运行，或改用 TOTP）；stdin 可按行喂两条（先口令后验证码），便于脚本：`printf '%s\n%s\n' "$PASS" "$CODE" | njuvpn start -config x.yaml`。

- 不引入：新的「服务端索要凭据」响应码。CLI 自己读配置就知道要不要问口令，少一层往返。

- 已定：**口令不回显**。用 `golang.org/x/term` 的 `ReadPassword`（Unix 走 termios 关掉 ECHO，Windows 走控制台模式，且负责 Ctrl-C 时恢复终端状态），读完后自己补一个换行。依赖：`golang.org/x/term` 本机模块缓存里没有，需联网拉取一次；已确认 `proxy.golang.org` 可达。
- 判定顺序：先 `term.IsTerminal(fd)`；不是终端（管道、cron、CI）时按普通行读取——那种场景本来就没有回显问题，`ReadPassword` 在非终端上会直接报错。
- 不加依赖的退路：用已有的 `golang.org/x/sys`（当前是 indirect 依赖，无需联网）手写关回显——Unix 用 TCGETS/TCSETS 清掉 ECHO|ICANON，Windows 用 GetConsoleMode/SetConsoleMode 清掉 ENABLE_ECHO_INPUT，约 60 行、两个平台各一份。能用 x/term 就用 x/term，手写版本容易漏掉信号恢复与 EOF 处理。
- 验证码保持现状（回显）：它是一次性的，且 `start` 流程里用户需要看到自己敲了几位。

- 工作量：中（单点都不大，但跨 CLI、IPC、服务、配置四处）。过度设计：否（用户明确要求）。

- 连带影响：

- 配置里 `password: ""` 会变成合法状态，config.example.yaml、README、HANDOFF 的用法说明都要跟着改（HANDOFF 里有多处 `njuvpn auth <code>` 的记录）。
- C3 的范围扩大：口令现在会经过 IPC 报文，回归测试除断言日志不含凭据外，还要断言服务进程不打印请求行（当前 server.go 确实不打印，需要把它固化成约束）。
- 口令与验证码的读取共用一个 helper，但提示语要区分（「口令」与「验证码」），且两条路径的回显设置相反。
- R4（auth_pending 超时）紧迫性下降：新流程里该状态只持续「CLI 提示 + 用户输入」这几秒；但用户直接关掉终端仍会留下它。
- 与 R6 相关：不要在一条待决的 IPC 请求里等用户输入（`start` 的 5 分钟超时会被吃满）；提示应发生在两次请求之间。

### C5 取消 `auth` 子命令的连带清理 —— 低

- 位置：cmd/njuvpn/main.go:44（usage）、:250-266、README.md:38、HANDOFF.md:104 / :199 / :230 / :380 / :470 / :496。

- 现状（核实）：usage、README、HANDOFF 都按「先 `start` 再 `auth <code>`」描述流程。

- 改法：删除 usage 与 README 里的 `auth`；HANDOFF 的时间线与用法改写成新流程；`probe -twf-id` 顺带支持从 stdin 读（TwfID 同样会进 history）。不扩大到隐藏 argv。

- 工作量：小。过度设计：否。

### C6 `probe` 会把本机正在跑的隧道踢掉 —— 中

- 位置：cmd/njuvpn/main.go:294
- 现状（核实）：probe 独立登录一次，占掉该账号唯一的会话名额，于是自己的隧道被踢、实例进入 error，短信模式下还要再花一条短信。
- 改法：probe 前先探活本实例；状态为 up / auth_pending 时打印警告并要求 `-force` 继续。
- 工作量：小。过度设计：否。

---

## 3. 启动 / 恢复 / 可观测性

### R1 UDP 端口在登录之后才绑定，端口冲突会白烧一次登录 —— 高

- 位置：internal/service/service.go:492（finishConnect 内才 NewDevice）、:512、internal/config/config.go:159（默认 51820）、internal/wireguard/bind.go:67
- 现状（核实）：第二个实例会完整走完登录 → 短信 → portal-token → query-ip（此时已消耗一次建隧道配额），最后才报 address already in use。`listen_port: 0`（系统分配）被 applyDefaults 覆盖，是死分支。
- 改法：`run` 启动时（登录前）按 listen_host 试绑一次端口并立即关闭，冲突即报错退出并点名 wireguard.listen_port。
- 工作量：小。过度设计：否。

### R2 `restart` 不等登出完成，可能谎报成功或留下空档 —— 高

- 位置：internal/service/server.go:295、cmd/njuvpn/main.go:145、:204-216、cmd/njuvpn/service_process.go:157
- 现状（核实）：退出顺序是「先关监听、再由 defer 登出」，所以 CLI 看到端点消失时旧进程可能还在登出（最长 10 秒以上）；紧接着的 `start` 会撞上学校侧「同一账号只允许一条会话」。另一种情况：旧进程仍答 pong 时 `restart` 会打印「已重启」，而机器上什么都没剩。
- 改法：`CmdShutdown` 处理里先同步完成 Close（含登出）再回包、再关监听；CLI 侧 serviceStopTimeout 15s → 30s；配合 M4 用 PID 校验答话者是刚拉起的新进程。
- 工作量：小-中。过度设计：否。

### R3 隧道躺平后既不自愈、也监控不到 —— 高

- 位置：internal/service/service.go:552、internal/vpn/tunnel.go:228、internal/service/server.go:160、cmd/njuvpn/client.go:86
- 现状（核实）：重连窗口 4 次约 30 秒，耗尽后 teardown 登出、进程留着、状态停在 error，没人敲 `start` 就永远不恢复。监控也发现不了：`status` 任何状态都返回 200（退出码 0），而 `start` 在已 up 时返回 409（退出码 1），cron 看门狗两种写法都不成立。
- 改法：`status` 增 `--check`（非 up 退出非 0）；`start` 幂等（已 up 打印「隧道已在运行」并退出 0）；error 收敛时日志明确写出恢复命令。
- 工作量：小。过度设计：否。

### R4 `auth_pending` 无超时，一直占着学校侧名额 —— 中

- 位置：internal/service/service.go:676-698
- 现状（核实）：未配 TOTP 时停在等人工输入，只能人工 `auth`，或再敲一次 start 丢弃旧会话重登（可能再花一条短信）。
- 改法：加可配超时（如 `auth_timeout: 10m`），超时后登出并回到 idle/error，日志写明原因。不做自动重发短信。
- 工作量：小-中。过度设计：否。

### R5 被拉起子进程的退出对 CLI 不可见 —— 中

- 位置：cmd/njuvpn/service_process.go:87-94、:109-120
- 现状（核实）：`cmd.Wait()` 的返回值被丢弃，子进程的致命错误只写进日志；CLI 只能干等 10 秒后说「请查看日志」。
- 改法：Wait 结果送进 channel，就绪轮询同时监听子进程退出；一旦退出就立刻报错并打印日志尾部若干行。
- 工作量：小。过度设计：否。

### R6 `stop` 会被正在跑的 `start` 挤到客户端超时 —— 中

- 位置：cmd/njuvpn/main.go:197、internal/service/service.go:174 / :220
- 现状（核实）：命令在 actor 里串行；`start` 最坏路径超过 3 分钟，而 `stop` 在 1 分钟处超时并返回错误，用户以为没生效，容易转向手工 kill（而手工 kill 会跳过登出）。
- 改法：`stop` 复用 cancelOp 先打断当前操作；或先把超时与文案对齐（「将在当前操作结束后断开」）。
- 工作量：中（取消语义）/ 小（只改超时与文案）。过度设计：否。

---

## 4. 学校侧协议与配额

### P1 query-ip 把 ServerReset 当作可重试，与配额期互相放大 —— 中

- 位置：internal/vpn/connect.go:214、internal/vpn/control.go:83
- 现状（核实）：一次 start 会连打 3 次、每次间隔 30 秒；而仓库自己的实测结论是遇到配额期应当停手等待。IpBusy 可重试是对的，ServerReset 在配额期重试只会继续被拒，还把账号推得更远。
- 改法：可重试集合只留 IpBusy；或把 ServerReset 的次数降到 1、间隔拉到分钟级。失败文案补「建议等几分钟再试」。
- 工作量：小。过度设计：否。

### P2 短信接口失败时 TwfID 被丢弃，会话可能永远登不出去 —— 中

- 位置：internal/vpn/portal.go:131（`return "", err`）、internal/vpn/connect.go:137、internal/vpn/session.go:264
- 现状（核实）：登录页与口令校验都已通过、只剩二次验证的会话，在 requestSMS 失败或响应无法识别时丢掉 TwfID，之后无法登出（TwfID 为空则不登出）。「该会话占名额直到服务端超时」是推断。
- 改法：`return twfID, err`，让上层能登出；保持既有约束「不误登出正在续用的会话」。
- 工作量：小。过度设计：否。

### P3 被踢 / 会话顶掉的文案不可操作 —— 中

- 位置：internal/vpn/control.go:49-70、internal/service/service.go:603
- 现状（核实）：IpKick 与 Shutdown 的文案没有提「同一账号只允许一条会话，可能已在别处（本机另一实例 / 另一台设备 / 学校官方客户端）登录」这条最有解释力的信息。
- 改法：各补一句。
- 工作量：小。过度设计：否。

---

## 5. 本地文件与其它（低优先级，可批量做）

### L1 /tmp 回退目录不校验属主与权限 —— 中

- 位置：internal/ipc/listen_unix.go:41
- 现状（核实）：`MkdirAll` 对「别人预先建好的 0777 目录」既不报错也不收紧权限；对方可以抢注套接字，之后 `auth <code>` 就发给对方进程。XDG_RUNTIME_DIR 存在时不受影响。
- 改法：建目录后校验属主是自己、group/other 无写权限，否则报错退出。
- 工作量：小。过度设计：个人机器上多余，共享主机上必要，一并做掉。

### L2 Windows 拿不到 SID 时的失败模式 —— 中

- 位置：internal/ipc/listen_windows.go:45-54
- 现状（核实）：DACL 退化成「仅 SYSTEM + Administrators」后，服务进程自己都连不上自己的管道，但仍继续监听并占住管道名，第二个实例起不来，只能手工杀。
- 改法：拿不到 SID 就明确报错并拒绝启动。
- 工作量：小。过度设计：否。

### L3 配置写回没有并发保护 —— 低

- 位置：internal/config/config.go:300、:332、cmd/njuvpn/main.go:135、internal/service/service.go:433
- 现状（核实 + 推断）：固定 `.tmp` 名 + 无条件覆盖私钥。两个进程同时首启同一份配置时，盘上的私钥可能与正在运行的那个进程内存里的不一致（之后所有客户端配置失效）；并发写还可能产出半截 YAML。
- 改法：临时文件名带 pid；写回私钥前重读文件，若 private_key 已非空则沿用文件里的值。不做 flock。
- 工作量：小。过度设计：部分（flock 属过度）。

### L4 一行级条目

- 日志文件名固定、无轮转（cmd/njuvpn/service_process.go:35）：默认名带上配置名；轮转交给 logrotate，不自研。
- `run -proxy` 不会被 restart 继承（cmd/njuvpn/main.go:108、:183）：start / restart 接受并透传 `-proxy`。
- `log.level` 只影响承载层日志且不校验取值（internal/config/config.go:156、internal/service/service.go:521）：示例写明或加校验。
- `listen_port: 0` 是死分支（internal/config/config.go:159、internal/service/service.go:640）：与 R1 一并决定——实现「系统分配」或删掉相关注释与日志。
- 428 与 200 共用退出码（cmd/njuvpn/client.go:86）：给 428 一个独立退出码，便于脚本判断。
- 文档与代码不一致六处：HANDOFF 的短信判据（应为倒计时 ≥150s）、classify.go:60 承诺但未实现的提示、main.go:107 过时的 systemd 注释、.gitignore 里指向不存在目录的 /state/、listen_port: 0、dist/ 里有 macOS 产物但无实测记录。
- 工作量：均为小。过度设计：否。

---

### 平台适用性（Windows / Linux）

绝大多数条目与平台无关——它们要么在平台无关的层（服务状态机、配置、学校侧协议、重试策略），要么在两端各有一份实现（IPC、私钥写回、配置路径）。按平台划分如下：

| 条目 | Linux | Windows |
|---|---|---|
| M1 端点按实例派生 | 适用 | 适用，且更必要：管道名是全局命名空间，默认值所有人同名 |
| M2 `-config` 失败即退出 | 适用 | 适用 |
| M3 / M4 / M5 | 适用 | M5 不适用（该变量是 Linux 概念）；M3 / M4 适用 |
| C1 配置文件权限 | 0600 + 拒绝过宽 | 若改成拒绝过宽要改用 ACL；建议只做「告知」。Windows 的 `%LOCALAPPDATA%` 默认可读本机所有用户，风险等同 |
| C2 / C3 凭据脱敏 | 适用 | 适用 |
| C4 / C5 CLI 改造 | 适用 | 适用：`golang.org/x/term` 两端都支持，Windows 侧无额外配置 |
| R1 端口预检 | 适用 | 适用，优先级更高：Windows 异常退出留下的 socket 会占住端口一段时间 |
| R2 restart 顺序 | 适用 | 适用 |
| R3 status 退出码 | 适用 | 适用，价值更高：Windows 没有 cron，检测手段本来就少 |
| R4 / R5 / R6 | 适用 | 适用 |
| P1 / P2 / P3 | 适用 | 适用 |
| L1 /tmp 目录校验 | 适用 | 不适用（无该回退路径） |
| L2 拿不到 SID 时拒绝启动 | 不适用 | 适用（已按 Windows 写） |
| L3 写回并发 | 适用 | 适用：`rename` 在 Windows 上目标已存在时可能失败，比 Linux 更需要 pid 后缀 |
| L4 文档不一致 | 大部分适用 | 六处中五处适用；`.gitignore` 的 `/state/` 是平台无关的 |

### Windows 专属观察

- **R3 在 Windows 上还有一条不同的失败路径**：`stop` 在 `StateIdle` 时返回 409（internal/service/server.go:234，隧道本来就没运行）。Windows 上「GUI 客户端退出 → 隧道已断 → 用户再点 stop」是常见操作，虽然与 R3 性质相同，但触发频率高得多。
- **命名管道没有「残留文件」问题，但有另一个 Windows 特有的坑**：拿不到 SID 时 DACL 退化（L2），进程继续监听并占住那个全局名字。

## 6. 明确不做

- IPC 加 token / 口令鉴权：文件权限 + OS 用户已经是边界，加协议只是自欺。
- 配置文件加密：挡不住 root，也挡不住运行期读内存；价值已被「盘上无明文」（C4）覆盖。
- 给 WireGuard peer 加 ACL、隐藏 argv：收益趋零（口令与验证码已由 C4 改走 stdin，argv 里不再有长期秘密）。
- 自研日志轮转、跨实例限流协调器、配置 flock、netns/cgroup 隔离、完整 CA 校验体系。
- 进程内自动重登：短信模式下会打爆配额与冷却。仅当配置了 TOTP 时才考虑，且必须长退避 + 限次。
- 证书指纹固定（TLS pinning）：加分项而非必需；要做也只加一个可选配置字段。

### 已核实、无需处理

- `replace_peers` 的作用域是本进程的 device，清不掉其它实例的 peer。
- allowed_ip 加 Mapper 双重校验：持有 peer 私钥者无法把隧道当任意源地址的跳板。
- 全程无特权操作；凭据从未进过 git；未发现 goroutine / 连接 / 句柄泄漏；状态机迁移路径完整；多实例复用同一个 10.66.66.2 是安全的。

---

## 7. 只做三件的话

1. **M1 + M2**：多实例隔离落到实处（端点按实例派生 + 显式 `-config` 失败即退出 + README 多实例一节）。当前最糟的失败形态是静默操作错账号。
2. **C1**：配置文件权限自动收到 0600，样例文件改 0600。一处改动挡住三样长期凭据。
3. **R1 + R2**：端口预检 + restart 的登出顺序。这两处直接烧学校的短信与会话配额，代价最大。

紧随其后：R3（可观测与恢复）、C2 + C3（凭据脱敏收尾）、P1（重试与配额）。

本批次另行确定、不参与上述排序：C4 + C5 的 CLI 改造。
---

## 8. 架构适用性（是否需要重构）

结论：**不需要重构**。改动落在现有分层内，绝大多数是局部修改。只有三处需要把职责从「多处各自默认」收敛到「一处决定」，属于小规模整理；另有协议形状上一处摩擦，有便宜的解法。

### 现成就能承接的机制（不动）

| 机制 | 位置 | 承接哪些条目 |
|---|---|---|
| actor：改状态的操作在单条命令通道上串行 | internal/service/service.go（Service 结构体与 loop） | C4 的凭据持有者放进去零锁成本；R4 的超时就是 loop 里多一个 case |
| 状态快照独立于 actor | internal/service/status.go | M4 加字段是加法 |
| 绑定注入点 | internal/wireguard/device.go:39（DeviceOptions.Bind） | R1 预开 socket 后注入，顺带消除 TOCTOU |
| 网络注入点 | internal/service/service.go（SetDialer / SetClientOptions） | 新增行为的测试不需要真实网络与账号 |
| 控制码分类 | internal/vpn/control.go:83 | P1 只改可重试集合 |
| IPC 已有 200 / 409 / 428 语义 | internal/ipc/protocol.go | R3 的退出码在 CLI 侧映射即可 |

### 需要收敛的三处（建议先做）

1. **端点解析**（M1 + M2 + M5）：`DefaultEndpoint` 两个平台各一份定义、共 6 处调用点（listen_unix.go:36 / :104、listen_windows.go:27 / :59、internal/service/server.go:268、cmd/njuvpn/client.go:62）。派生需要配置路径，而路径只有调用方手里有 → 收敛成 `ipc.EndpointFor(configPath)`（ipc 不依赖 config，保持叶子；canonical 化与哈希都在这里），`Listen` / `Dial` 改为只接受显式端点。
2. **凭据持有**（C4）：`s.cfg.Password` 现在被读两处（internal/service/service.go:341、:387），两处都在 actor 协程内，换成 actor 私有的凭据结构不需要加锁。顺带把 cfg 变成只读（现在 `wg-peer` 会写 `s.cfg.WireGuard.PeerPublicKey`）。
3. **关闭顺序**（R2）：职责现在分在 service.RunServer、Server.Shutdown、cmd 的 `defer svc.Close()` 三处，这正是 R2 的成因。收敛成一个关闭序列：停止接受 → 排空在处理的请求 → 登出。

### 唯一的协议摩擦

C4 传口令与 M4 校验身份都会压到「一行文本、空白切分」的 IPC 协议上。口令用 base64 解决；身份校验建议加一条机器可读的命令（例如 `whoami` → `200 pid=<n> config=<base64> endpoint=<base64>`，含空格的取值一律编码），只在需要校验的地方调用，其余协议不动。不建议换成 JSON 或给协议加头字段——收益配不上改动面。

### 建议落地顺序

先做结构性的三处（端点 → 凭据 → 关闭顺序），它们互相有依赖：身份校验依赖端点派生，R3 的巡检依赖身份字段。其余条目按严重度推进，彼此独立。

### 已知的模型瑕疵（顺手清理，不阻塞）

- `Service` 持有并原地修改 `*config.Config`，配置同时承担「只读输入」与「可变状态」两种角色；C4 落地后凭据会只存在于内存，两者容易混淆。
- 日志文件名与实例身份耦合在 cmd 层（service_process.go:35），而日志前缀在同进程的 `log` 全局上——多实例时这两处都要带实例标识，实现时要一起改。
