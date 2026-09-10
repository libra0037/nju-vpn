# njuvpn 代码审查清单（2026-09-10）

来源：四个独立子 agent 分区审查（协议层 / 服务与 CLI / 承载与 IPC / 拨号与配置），
再由我逐条人工核实关键项（含读 wireguard-go 与标准库源码、算术验证、git blame）。

**怎么用这份清单**：每条都有编号与「建议」。你回复编号即可，例如
「A1 A2 A3 同意；C1 改成只在解析失败时报警；E 全部删除」。
未确认的条目我不会动。

**前提**：这是个人使用的客户端，Windows 与 Linux 都要能用 —— 一台机器、一个用户，
服务进程与 CLI 都由你本人启动，不对外提供服务。凡是只对「同机其他用户 / 同机敌意进程」
成立的加固，已归入 **G 组**，默认不做。D 组剩下的是单用户下依然成立的（网络路径、日志、依赖）。

## 0. 已决定的方向（2026-09-10）

1. **两个平台都要能用**：Windows 与 Linux（Ubuntu 主力机）都是目标平台，不是「Linux 只用来跑测试」。
2. **砍掉 kardianos / 系统服务安装（B5 采纳）**：
   - 删 `njuvpn service install|uninstall|start|stop|restart|status`、`internal/service/install.go`、
     `windowsProgram`、kardianos 依赖
   - 服务进程由 CLI 按需拉起：`njuvpn start` 探端点 → 不在就 detached spawn `njuvpn run` → 轮询 `ping` 到就绪
   - 新增 IPC `shutdown`（收尾含登出）与 CLI `njuvpn restart`（改配置 / 重置进程）
   - 开机自启：Windows 用任务计划程序「登录时启动」；Linux 手写 systemd **user** unit
   - 因此作废：**B1、B2、B4、D8、F2**；**B3** 退化成「spawn 出来的子进程天然是当前用户」
3. **单用户假设**：**G1–G4 不做**；**G5 保留**（只改注释）。
4. **默认路径改到用户目录**：
   - 配置：Windows `%LOCALAPPDATA%\njuvpn\config.yaml`，Linux `~/.config/njuvpn/config.yaml`（A1 按此修）
   - IPC 端点：Linux `$XDG_RUNTIME_DIR/njuvpn.sock`（回落 `/tmp/njuvpn-<uid>.sock`），Windows 命名管道不变

以上是方向；A / C / D / E / F 组的具体条目仍逐条待确认。

---

## 进度（2026-09-10 晚，按批次提交）

| 批次 | 提交 | 内容 |
|---|---|---|
| A + G + B3a | `1b9d2ed` | A1–A5 全修；G1/G2/G4 删除、G5 改注释；端点默认值移到 `$XDG_RUNTIME_DIR` |
| B5 | `8a58738` | 去掉 kardianos 与系统服务安装；CLI 按需拉起 + `shutdown` / `restart` |
| C | `29ada46` | C1–C13、C15–C18（C14 见下） |
| D + E | `bbccc64` | D1/D4/D10（D9 随 C 批一起做）；E1–E3、E5 |
| 文档 | `c3f20f4`、`00193dc` | 进度记录；新形态在 Windows 上的端到端实测 |
| E4 + F + C14 | 本次 | vpntest 死代码与轮询等待、F1–F16（F2 已作废）、重连期间的状态显示 |

新形态已在 Windows 上端到端跑通（2026-09-10 晚，笔记本）：CLI 拉起服务进程 142ms 就绪，
随后 start → 短信 → up → stop 全程正常，见 HANDOFF 第 11 节。

已经作废、不需要再动的：B1、B2、B4、D2、D3、D5、D6、D7、D8、F2。

清单里已无待处理项。剩下两件与真机有关：在 Ubuntu 上跑通、配置开机自启。

过程中发现并顺手修掉的（原清单没有）：

- `SMSCooldown` 的正则只认「N 秒内请勿重复请求」，冷却期内真正该显示的
  「还需等待 N 秒」反而取不到值。
- UDP 分支的校验和钳位一开始被补到了 TCP 分支（两处代码相邻），
靠新增的回归测试才发现。


## A. 立刻修（会伤到正在用的链路）

### [ ] A1 Windows 默认配置路径是坏的 —— **我自己引入的回归**

- **位置**：`internal/config/config.go:69`
- **问题**：字符串里的反斜杠全部丢失，njuvpn 被吃成 juvpn，中间还有一个真实换行。

      func DefaultPath() string {
          if runtime.GOOS == "windows" {
              return `C:ProgramData
      juvpnconfig.yaml`
          }
          return "/etc/njuvpn/config.yaml"
      }

- **触发**：Windows 上不带 -config 运行；service install 注册的命令行正是 run，所以开机自启必然走这条路。
- **后果**：报错为「读取配置文件 C:ProgramData↵juvpnconfig.yaml: 系统找不到指定的路径」，用户看不出该改什么；配了重启策略的服务会反复失败重启。
- **来源**：git blame 指向 125e611（我的重构提交）。Linux 分支不受影响，所以 CI 永远跑不到。
- **建议**：把路径取值抽成不依赖 runtime.GOOS 的函数并加单测（现在这样手工拼接，Windows 分支在 Linux CI 上永远编译不到）。默认值改到哪见 **G1** —— 我倾向用户目录（%LOCALAPPDATA% 下的 njuvpn 目录），比 ProgramData 更贴合 B3 的登录用户身份，也不用再管 ACL。同时全面搜一遍我写过的地方有没有同类丢失（我已检查，这是唯一一处）。

### [ ] A2 承载层会因为「一个装不下的包」把自己关掉

- **位置**：`internal/wireguard/relay.go:201`
- **问题**：Read 在缓冲区装不下时返回错误，而 wireguard-go 的 TUN 读协程收到非 os.ErrClosed 错误会执行 go device.Close()。

      if len(pkt) > len(dst) {
          r.countDrop()
          return 0, fmt.Errorf("wireguard: 包长 %d 超过缓冲区 %d", len(pkt), len(dst))
      }

- **证据**：wireguard-go 的 device/send.go，RoutineReadFromTUN 里：

      if !device.isClosed() {
          if !errors.Is(readErr, os.ErrClosed) {
              device.log.Errorf("Failed to read packet from TUN device: %v", readErr)
          }
          go device.Close()
      }
      return

- **缓冲区是平台相关的**：MaxSegmentSize 在 Windows 上是 2048-32（可用 2000 字节），Linux 上是 65535；而我们的 splitPacket 允许切出最大 65535 的包。
- **后果**：Windows 部署上一个超过 2000 字节的下行包就会静默关掉承载层。status 仍显示 up、wg-stats 仍能读（UAPI 不做关闭检查），但流量彻底没了，必须 stop + start。校园网内通常 1500 MTU，所以是潜在而非必现。
- **建议**：装不下就丢包并 return 0, nil（wireguard-go 会重新调用 Read）。同步改 relay_test.go:211 那条把它钉成「必须报错」的用例。

### [ ] A3 Session.Run 返回时不关自己刚建立的两条流

- **位置**：`internal/vpn/session.go:122`（s.track(rx) 之后）
- **问题**：三条返回路径（recvErr / sink.Done / ctx.Done）都没有关闭 rx 与 tx；只有 ctx 取消时那个 context.AfterFunc 会关。文件里 Run 的注释写的却是「返回后不会再留下任何 goroutine 或连接」。
- **触发**：下行流先死（正常会发生）。RunWithRetry 立刻重入 Run，每轮留下上一轮的两条连接；一次断线最多同时挂 4 组死连接，服务端侧的流也一直占着。
- **建议**：s.track 之后两行 defer rx.Close() 与 defer tx.Close()（net.Conn.Close 幂等）。加一条回归测试：连续两次 Run 失败后，服务端观测到上一轮的连接已关闭。

### [ ] A4 njuvpn probe 在验证码提示处失败时不登出

- **位置**：`cmd/njuvpn/main.go:390`
- **问题**：askCode 失败直接 return promptErr，而清理由 defer 注册在这之后；Connect 保证返回的 sess 已带 TwfID。

      prompted, promptErr := askCode(authErr.Kind)
      if promptErr != nil {
          return promptErr          // 这里返回，下面的 defer 还没注册
      }

- **触发**：probe < /dev/null、或提示时按 Ctrl-C / Ctrl-D。
- **后果**：服务端留下占名额的会话，下次建隧道被拒（同一账号只允许一个客户端）。
- **建议**：把清理注册挪到第一次 Connect 之后立刻执行，或用变量承接「当前归我负责的会话」并在每条返回路径上关闭。

### [ ] A5 退出期间仍可能挤进一条新命令

- **位置**：`internal/service/service.go:226`（dispatch）与 :209（call）
- **问题**：call 与 loop 两端的 select 都同时含 s.cmds 与 s.closed，两者都就绪时 Go 随机选；dispatch 里没有已关闭检查。
- **触发**：Ctrl-C / SIGTERM 的同时，另一个终端跑 start。
- **后果**：Close 最多等 20 秒后放弃，进程带着「已拿到 TwfID 但没登出」的状态退出。
- **建议**：dispatch 开头加一次非阻塞检查 —— 若已关闭且命令不是 cmdTunnelDown，直接 reply(ErrShuttingDown) 并返回。

---

## B. 进程模型与安装路径（B5 已定，其余待确认）

> 结论先行：**服务进程不需要任何特权**（B3 有逐项核实）。现在 Windows 上跑着的实例就是普通用户会话里
> `Start-Process` 拉起来的，`start` / `auth` / `status` 都正常。
>
> **已定方向（第 0 节）**：砍掉「安装系统服务」这一层，服务进程由 CLI 按需拉起，两个平台都走这条路。
> 因此 **B1 / B2 / B4 与 D8 / F2 一并作废**（它们都长在 SCM 或 kardianos 安装路径上），
> **B3 退化成「spawn 出来的子进程天然是当前用户」**。本节真正要做的只剩 **B3a** 与 **B5 的实现**。

### B1 windowsProgram.Stop 会永久等待 —— **已作废（见 B5）**

- **位置**：`internal/service/run_windows.go:33`
- **问题**：Stop 先 svc.Close() 再等 &lt;-p.done，而 p.done 只在 RunServer 返回时关闭；Windows 服务上下文收不到信号，RunServer 永远不会返回。

      func (p *windowsProgram) Stop(service.Service) error {
          p.svc.Close()
          if p.done != nil {
              &lt;-p.done          // 永远等不到
          }
          return nil
      }

- **后果**：SCM 等满 WaitToKillServiceTimeout（默认 20 秒）后 TerminateProcess，停止请求报 1053；若登出恰好慢过这个上限，被截断的正是登出。
- **建议**：让 RunPlatform 独占 listener 所有权 —— ipc.Listen 后交给 NewServer，Stop 里 srv.Shutdown() + svc.Close()，done 通道整个删掉。

### B2 Start 吞掉 IPC 启动错误，SCM 认为服务已就绪 —— **已作废（见 B5）**

- **位置**：`internal/service/run_windows.go:22`
- **问题**：RunServer 在后台协程里跑，启动错误只写进 log（服务进程无控制台），Start 无条件返回 nil。
- **后果**：服务显示 running，而所有 CLI 命令报「服务是否在运行？」，没有线索指向配置错误。
- **建议**：同上 —— 把 ipc.Listen 提到 Start 里同步执行，失败即 return err（kardianos 会把它变成「启动失败」）。

### B3 服务必须以普通用户运行 —— 它不需要任何特权（已定：CLI 拉起即天然满足）

- **结论**：服务端没有任何需要提升权限的操作。代码审查确认：
  - 不创建网卡：全仓库没有 `wintun` / `tun.Create` / TUN 相关调用；承载层是内存里的 `Relay`（`internal/wireguard/relay.go`）
  - 不动路由、不提权：没有 `netlink` / `route` / `AdjustTokenPrivileges` / `SeCreateGlobalPrivilege`
  - 端口不是低端口：默认 51820，用户态 UDP 只要大于 1024 就无需特权
  - 只写自己目录下的文件：配置文件、私钥写回、IPC 端点
  - **实机已验证**：当前正在跑的实例就是用普通会话的 `Start-Process` 拉起来的（`C:\Users\<用户名>\njuvpn\`，未提权），`start` / `auth` / `status` 全部正常
- **问题**：`serviceConfig` 没有设置运行账户，于是两个平台都落到特权账户上：

      return &service.Config{
          Name:        ServiceName,
          DisplayName: ServiceDisplayName,
          Description: ServiceDescription,
          Arguments:   args,
          Option: service.KeyValue{ ... },
      }                    // 没有 UserName —— Windows 落到 LocalSystem，Linux 落到 root

- **后果链（Windows）**：命名管道的 DACL 由 `currentUserSDDL()` 按**进程当前用户**生成。以 LocalSystem 运行时得到的是 `SY` + `BA` + SYSTEM 自己，**不含交互用户**；而 UAC 之后的普通令牌里 `BUILTIN\Administrators` 是 deny-only SID，所以它也不是「管理员」。

     五个子命令（start / stop / status / auth / wg-peer）走的是同一条
     ipc.Dial -> winio.DialPipe 路径，权限判定完全同构 —— 不存在某个命令
     能漏过去。要么全通，要么在 connect 阶段全被 ERROR_ACCESS_DENIED 挡住。

  （提权后的终端能连上 —— 那种令牌里 BA 是启用的。但那就要求用户每条命令都开
  管理员终端；而服务卡在 `auth_pending` 等用户输码时，你偏偏输不进去，每次重试
  还要再烧一条短信。这本身也说明账户选错了。）
- **后果链（Linux）**：unit 无 `User=`，服务以 root 常驻，处理账号口令的进程不该有这种权限；同时端点 `/run/njuvpn.sock` 需要 root 才能 bind，普通用户跑 `njuvpn run` 会直接 permission denied。
- **修法**：让服务以调用安装的那个用户运行。两个平台各一条路：

| 平台 | 做法 | 连带效果 |
|---|---|---|
| Windows | **由 CLI 按需拉起**（`start` 发现没有活实例就 detached spawn `run`，子进程继承你的令牌）；要开机就有再加一条任务计划程序登录触发 | 五个命令都无需提权，也不必存密码 |
| Linux | 用 user unit：kardianos 支持 `UserService: true`，会写 `~/.config/systemd/user/njuvpn.service` 并调 `systemctl --user`；模板里只有 `User={{UserName}}`，**没有 Group 行** | 但**端点必须同时改**，见 B3a |

- **不要**走「给 SYSTEM 进程的管子放宽 DACL」这条路：那比换运行账户更复杂也更弱，根因就是账户选错了。
- **推荐**：见 **B5** —— 建议整体砍掉 SCM 与 kardianos，改由 CLI 按需拉起，另加 `shutdown` / `restart`；Linux 若保留，用 systemd user unit + `$XDG_RUNTIME_DIR` 端点。

### [ ] B3a 端点位置：用 $XDG_RUNTIME_DIR，让普通用户也能 bind

- **位置**：`internal/ipc/listen_unix.go:13`（`DefaultEndpoint` 返回 `/run/njuvpn.sock`）
- **问题（功能，不是安全）**：`/run` 只有 root 能写。B3 把服务改成普通用户之后，Linux 上 `njuvpn run` 会直接 permission denied。
- **顺带**：`MkdirAll(dir, 0700)` 对已存在的 `/run` 是空操作 —— 注释声称收紧了目录，实际什么都没做。
- **修法**：`DefaultEndpoint` 改成 `filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "njuvpn.sock")`，取不到时回落到 `/tmp/njuvpn-<uid>.sock`，并且保留 `Listen` 里的 `chmod 0600`（一行，无害）。
- **说明**：原来挂在这条上的「先 bind 后 chmod 的权限窗口」（旧 D6）防的是同机其他用户，按 **G 组**不做；这条降级为纯功能性修复。
- **已定**：两个平台都要能用（Windows + Ubuntu），Linux 侧不是「只用来跑测试」，这条照做。
  注意 `internal/ipc` 的 unix socket 运行时**整体保留** —— 删掉它会让 Linux 上编译不过、测试也跑不起来。
- **注意**：Windows 侧不受影响（端点固定是命名管道），所以这条只改 Linux 分支。

### B4 安装时的服务选项要按平台生成（现有三个在 Windows 上一个都不生效）—— **已作废（见 B5）**

- **位置**：`internal/service/install.go:32`
- **证据**：kardianos v1.3.0 的后端读取的键完全不同：

| 键 | systemd (Linux) | Windows SCM |
|---|---|---|
| `Restart` | ✅ 读取 | ❌ 忽略 |
| `SuccessExitStatus` | ✅ 读取 | ❌ 忽略 |
| `RestartSec` | ❌ **模板硬编码 120 秒**（写了也没用） | ❌ 忽略 |
| `OnFailure` | ❌ 忽略 | ✅ 读取 |
| `StartType` / `DelayedAutoStart` | ❌ 忽略 | ✅ 读取 |

- **后果**：注释想表达「重启间隔压到 5 秒」，实际 Linux 上是 120 秒（崩溃循环时每次等两分钟）；Windows 上没有 `OnFailure`，服务崩溃后**没有任何恢复动作**，与代码里 `Restart: on-failure` 的字面意图相反；`SuccessExitStatus: "0 2"` 在当前实现下也是空转 —— 所有 FlagSet 都是 `ContinueOnError`，参数坏掉走的是 exit 1，`run` 这条路几乎不可能返回 2（2 只在第一个参数缺失或未知时出现，而那正是该重启的情形）。
- **修法**：按平台生成 —— Linux 保留 `Restart` + `SuccessExitStatus`，删掉不会被读取的 `RestartSec`（并把注释改成「实际 120 秒，改这个值需要自定义 unit 模板」）；Windows 用 `OnFailure: "restart"` + `OnFailureDelayDuration`。
- **与 B3 的关系**：如果 Windows 改用任务计划程序（B3 的推荐路径），这条的 Windows 分支就退化成「配好触发条件与重启策略」；Linux 分支照上面改。

### B5 进程生命周期：砍掉 SCM 与 kardianos，改由 CLI 按需拉起（已决定，待实现）

**先看两个事实**

1. **装成服务 ≠ 开机就能用**。`cmdRun` 只加载配置、必要时生成私钥，然后进 `RunPlatform`；建隧道与启动 WireGuard 承载都在 `njuvpn start` 里（`finishConnect` 里的 `s.setDevice(dev)`）。服务起来只是把 IPC 端点架好，隧道要等一条 start 才建。
2. **状态机异常不需要重启进程**。`start` 明确接受 `StateIdle` 与 `StateError`（service.go:274 的分支），重敲一次就从干净状态重来；`awaitAuth` 是立刻返回的，等验证码时 actor 空闲，`stop` 照常可用。真正需要重启进程的只有两件事：**改了配置要重载**、**进程卡死**。

而目前没有任何 IPC 命令能让服务进程退出（只有 start / stop / status / auth / ping / wg-peer / wg-stats）。Windows 上只能 Stop-Process 硬杀 —— `defer svc.Close()` 不执行，跳过登出，服务端留一个占名额的会话。

**已定的形态**

| 需求 | 做法 |
|---|---|
| 把服务拉起来 | `njuvpn start` 先探测端点，连不上就 detached spawn `njuvpn run`，再轮询 `ping` 到就绪（E3 的 CmdPing 从死代码变成必需） |
| 优雅重置 | 新增 IPC `shutdown`：收尾（含登出）后退出；`njuvpn restart` = 限时 shutdown → 必要时按 pidfile 强杀 → 重新 spawn |
| 重载配置 | 同上。改完 config.yaml 跑 `njuvpn restart`，不必再杀进程 |
| 开机就有 | 可选：Windows 任务计划程序「登录时启动」，或 Linux systemd user unit（见下）。都不存密码 |

**随之消失**：`service install/uninstall/control`、install.go、windowsProgram、kardianos 依赖；清单里的 **B1、B2、B4、F2、D8** 一并作废；**B3** 退化成「spawn 出来的子进程天然是当前用户」，不需要 `UserName`，也不需要存密码。

**Linux 的自启**：手写一份 systemd **user** unit（`~/.config/systemd/user/njuvpn.service`，`systemctl --user enable --now njuvpn`），要免登录也运行再加 `loginctl enable-linger`；套接字自然落在 `$XDG_RUNTIME_DIR`。不依赖 kardianos —— 它的模板硬编码 `WantedBy=multi-user.target`（用户单元应为 `default.target`，**待实机确认**）与 `RestartSec=120`，两个值都不对路，而我们要的只是一行执行命令。

**已定**：两个平台都要能用（Windows + Ubuntu），所以 `internal/ipc` 的 unix socket 运行时保留；删掉的是「安装系统服务」这一层。理由见总览第 0 节。

### 说明：B 组的相互关系

- **B5 是主改动**：删掉安装系统服务这一层，两个平台都由 CLI 按需拉起，另加 `shutdown` / `restart`。B1 / B2 / B4 与 D8 / F2 随它作废。
- **B3a** 仍然要做：端点位置（Linux 用 `$XDG_RUNTIME_DIR`）与运行账户无关，是普通用户能否启动服务的前提。
- **D6** 已被 B3a 吸收，不再单独处理。

## C. 协议与边界正确性

### [ ] C1 改写地址后 UDP 校验和可能是 0x0000（应为 0xffff）

- **位置**：`internal/wireguard/mapping.go:110`
- **问题**：RFC 768 规定「计算值为 0 时线上写全 1」；写成 0x0000 会被接收端解释为「发送端没算校验和」从而跳过校验。
- **证据**：同一份算法用 100 万随机样本对照 —— 增量结果与全量重算**不一致 0 次**（算法正确），但「改写后恰为 0」出现约 24 次。
- **建议**：if c == 0 { c = 0xffff }。注意 mapping_test.go 的辅助函数已经这么做了，只有实现漏了。

### [ ] C2 写回私钥时丢掉该行的行尾注释

- **位置**：`internal/config/config.go:296`
- **问题**：算出了 indent 却整行重建，于是行尾注释与引号风格一起丢。样例文件里 private_key: "" 后面跟的注释正是这个形状，而函数注释承诺「保留原有注释」。
- **测试盲区**：persist_test.go:37 只检查了**其它行**的注释还在。
- **建议**：只替换值区段 —— 找到 field + ":" 之后的值结束位置（遇到 # 前的空白为止），拼 line[:valueStart] + value + line[commentStart:]。不需要引入 yaml.Node（实测会规范化整份文件，与「文件是给人看的」冲突）。

### [ ] C3 listen_port: 0 被静默改成 51820

- **位置**：`internal/config/config.go:157`
- **问题**：applyDefaults 把 0 一律当「未设置」，而 validate 明确允许 0，样例文档也承诺「填 0 表示由系统分配」，承载层确实支持（bind.go:75、device.go:149 会读回真实端口）。
- **后果**：想用临时端口的用户拿到 51820，可能撞占用，且无提示。
- **建议**：要么支持 0（字段改成指针或 -1 哨兵），要么把样例文档改成「必须显式指定端口」。我倾向后者 —— 少一个状态。

### [ ] C4 SOCKS5 请求恒用域名型（ATYP=0x03）

- **位置**：`internal/dial/dial.go:227`
- **问题**：IP 字面量被当域名交给代理解析（server_ip 配 IPv6 时必然失败）；byte(len(host)) 在 256 字节时回绕成 0；uint16(port) 对越界静默截断。
- **建议**：加 3 行分支 —— To4() 非 nil 用 0x01、To16() 非 nil 用 0x04、其余 0x03，并检查 len(host) <= 255 与 1 <= port <= 65535。

### [ ] C5 Unix 侧 Dial 没有超时（Windows 侧有 5 秒）

- **位置**：`internal/ipc/listen_unix.go:96`
- **后果**：服务进程活着但不再 accept 时，任意 CLI 命令会永久挂在 connect()；client.go 的 SetDeadline 在 Dial 之后才生效，救不了。
- **建议**：net.DialTimeout("unix", endpoint, 5*time.Second)。

### [ ] C6 代理 URL 缺主机名时不报错，静默连本机

- **位置**：`internal/dial/dial.go:63`
- **问题**：proxy 写成 "http://" 时 url.Parse 成功、Host 为空，JoinHostPort("", "80") 得到 :80，net.Dial 把空主机名当本机。
- **建议**：New 里在 scheme 判定后加一句 if u.Hostname() == "" 就报「代理地址缺少主机名」。

### [ ] C7 代理返回带 Content-Length 的 200 会吃掉隧道开头若干字节

- **位置**：`internal/dial/dial.go:110`（resp.Body.Close()）
- **触发**：不合规代理（RFC 9110 禁止 2xx CONNECT 带 Content-Length）。合规代理不受影响 —— agent 核实了 NoBody 与 HTTP/1.0 风格两条路径都安全。
- **后果**：隧道建立后协议层读到的第一个字节不是服务端的，握手报「响应不符合协议」，现场看像是服务端的问题。
- **建议**：删掉那行 resp.Body.Close()，或只在非 200 时关闭。

### [ ] C8 validateHost 放过 [::1] 这种带方括号的写法

- **位置**：`internal/config/config.go:228`
- **后果**：ServerAddr() 产出 [[::1]]:443，报错里是个语法不成立的地址。
- **建议**：显式拒绝方括号、百分号、@。

### [ ] C9 retryable 把协议不符也当可重试，会白烧配额

- **位置**：`internal/vpn/tunnel.go:248`
- **问题**：只对 ControlError 判断，其余一律 true。服务端回非预期字节（ProtocolError）时 acquireIP 会再试 3 次、每次退避 30 秒。
- **后果**：协议不符不会自愈；HANDOFF 记的正是「密集重试会把账号打进被拒状态」。
- **建议**：把 ProtocolError 归为终止性（errors.As 一次）。

### [ ] C10 成功的连接在 Trace 里留下两条 query-ip 记录

- **位置**：`internal/vpn/connect.go:210`（acquireIP 内部已 add 过一次）
- **后果**：probe 打印的阶段表里 query-ip 出现两次，第二条恒为 0s，「全部 N 个阶段」也被算大。
- **建议**：让 acquireIP 独占该阶段记录，删掉 connect.go:202 与 :210。

### [ ] C11 标签正则不跨行

- **位置**：`internal/vpn/parse.go:34`
- **问题**：Go 的点号默认不匹配换行。多行 CDATA 的 Message 会取不到，于是报成「缺少该标签」—— 很误导。顺带：同一行出现两个同名标签时，贪婪匹配会从第一个开标签吃到最后一个闭标签。
- **现状**：实测样本都是单行，属潜在项。
- **建议**：改成 (?s)(.*?)。

### [ ] C12 setPeer 部分失败时设备已改、内存配置没改

- **位置**：`internal/service/service.go:406`
- **触发**：config.PersistPeerPublicKey 失败（文件被移走、目录不可写）。
- **后果**：CLI 报错，但设备已在用新公钥；隧道重建时又用回旧公钥，客户端表现为「接不上」，日志只说「写回配置文件失败」。
- **建议**：把持久化放在动设备之前，失败即返回、设备不动。

### [ ] C13 auth 客户端超时 2 分钟小于服务端最坏约 3 分钟

- **位置**：`cmd/njuvpn/main.go:223`
- **问题**：服务端路径含 submitCode + portalToken + acquireIP（3 次尝试 x 30 秒退避）。
- **后果**：客户端 i/o timeout 退出码 1，服务端仍在继续并把隧道拉起来（用户以为失败）。
- **建议**：提到与 start 一致的 5 分钟。

### [ ] C14 隧道重连期间状态仍对外报 up（最长约 30 秒）

- **位置**：`internal/service/service.go:508`
- **问题**：状态先进 up 再起隧道协程，而 RunWithRetry 失败后要退避 2+4+8+16 秒才返回。
- **后果**：status / wg-stats / Clash 看到「已建立」而实际没有流量。
- **建议**：在 Run 第一次失败时经 actor 上报一次「重连中」的 detail。UI 细节，可以往后放。

### [ ] C15 隧道协程没有 panic 边界

- **位置**：`internal/service/service.go:517`
- **问题**：dispatch 的 recover 只保护命令执行；隧道协程（以及 readLoop）panic 会直接终止进程，而 main 的 defer svc.Close() 在别的协程上不会执行。
- **现状**：agent 逐个查过 endpoint 与 mapping 的切片与回调，**没有构造出可达的 panic** —— 这是「保证不成立」而非已知必现缺陷。
- **建议**：给该协程加 recover，转成 reportTunnelDown（它已经能安全地把结果送回 actor）。

### [ ] C16 第二个信号会跳过登出

- **位置**：`internal/service/server.go:263`、`cmd/njuvpn/main.go:471`
- **问题**：两处都在收尾还没完成时就 signal.Stop，默认动作（立即终止）随之恢复。
- **触发**：交互式 run 下连按两次 Ctrl-C；或 probe 时第二次 Ctrl-C。
- **建议**：把信号捕获的生命周期延长到收尾完成之后；两处合并成一个共享 helper。

### [ ] C17 start 的状态错误被报成 500（语义应为 409）

- **位置**：`internal/service/server.go:156`
- **触发**：隧道已在跑时再敲一次 njuvpn start（很常见）。
- **后果**：CLI 打印「服务进程返回 500」并以退出码 1 结束，脚本把「已经在运行」误判成服务端故障。
- **建议**：加一个可判定的哨兵错误（如 ErrBadState），在 dispatch 里统一映射成 409。

### [ ] C18 Server.Wait 零调用导致正在处理的请求被进程退出截断

- **位置**：`internal/service/server.go:100`（方法）与 :265（RunServer 直接 return）
- **问题**：Shutdown 之后正在处理的那条请求没人等。被截断的可能正是一条**已经成功、只差回包**的 start 或 auth：客户端拿到 EOF 报错、退出码 1，服务端其实已经完成动作。
- **建议**：Serve 返回后加 srv.Wait()（带超时）再进登出；或删掉该方法并把注释改成「不等待在处理的连接」。我倾向前者。

---

## D. 安全（单用户假设下仍然成立的）

### [ ] D1 全链路关闭证书校验，而口令加密用的公钥来自同一条未认证通道

- **位置**：`internal/vpn/client.go:170`（portal uTLS）、:185（隧道）、:242（HTTP Transport）
- **问题**：server_ip 是官方支持的配置项，实际建连目标是裸 IP，连 DNS 名字绑定都没有。攻击者替换 RSA_ENCRYPT_KEY 就能解出明文口令；TWFID 直接在 Cookie 头里，同样可被读走。
- **附带**：parsePublicKey 只校验 E 大于等于 3 与 N 大于 0，不校验模数位数（1024 位的下限检查只写在 live_test.go 里）。
- **建议**：三选一 —— (a) 加证书或公钥指纹 pin（配置项存 SHA-256）；(b) 至少在 parsePublicKey 里拒绝小于 1024 位的模数；(c) 明确写进文档「口令保密性等价于无主动 MITM」，不留「RSA 加密等于安全」的错觉。**我倾向 (b)+(c)** —— pin 会限制服务端换证书时的可用性，而这是一个每天要用的工具。

### [ ] D2
配置文件权限校验 —— 防的是同机其他用户，已移入 **G1**，单用户假设下不做。

### [ ] D3
IPC 对端校验 —— 需要同机的第二个用户或敌意进程才成立，已移入 **G2**，默认不做。

### [ ] D4 短信接口的原始响应被写进日志

- **位置**：`internal/vpn/portal.go:178`
- **问题**：这是我为了诊断冷却判据加的。注释说「内容只有脱敏手机号」，但实测样本里是**真实手机号的前 3 后 4 位**加上 USER_PHONE 字段；而且响应标签集合由服务端决定，login_sms1.csp 会回 TwfID —— 一旦这个接口也回，会话标识就进日志了。
- **建议**：只记分类结果与倒计时（ErrSMSSent / ErrSMSStillValid 加秒数）。需要原文时用已有的 TestLiveSMSDiagnostic，那本来就是为取样本设计的。

### [ ] D5
验证码经 argv 的可见性 —— 前提是机器上有别人，已移入 **G3**，默认不做。

### [ ] D6
套接字位置与权限窗口 —— 功能那半条（`/run` 普通用户写不进）并入 **B3a**，权限窗口那半条归 **G 组**不做。

### [ ] D7
IPC 连接槽位上限 —— 占满需要同机敌意进程，已移入 **G4**，默认不做。

### D8 安装时的 NJUVPON_CONFIG 环境变量会决定服务进程读哪份配置 —— **已作废（见 B5）**

- **位置**：`internal/service/install.go:119`
- **问题**：变量名拼写有误（少一个 V），而它把结果写进服务的启动参数：只要安装者的环境里设过这个名字，服务读的就是另一份配置，而且不会有任何提示。B3 之后服务以普通用户运行，「特权账户读用户可写的文件」这半条自动消失，剩下的是拼错的变量名会静默改变行为。变量也没出现在 usage() 里。
- **建议**：安装路径只用显式的 -config。

### [ ] D9 远程 HTTP 或 SOCKS5 代理的凭据是明文发出的

- **位置**：`internal/dial/dial.go:75`
- **说明**：这是协议本身的性质，不是实现错误（https 代理已经走 TLS）。但代码把「凭据明文」当作给 https 加 TLS 的理由，却对 http 加密码加远程主机这个组合既不警告也不拒绝，样例配置还写着「支持 http 与 socks5 两种写法」。
- **建议**：URL 带 User 且主机不是 loopback 时打印警告，或文档写清「带密码只应指向本机代理」。

### [ ] D10 标准库自身有 17 个已知漏洞

- **来源**：govulncheck
- **问题**：当前工具链是 go1.26.0，17 个漏洞（crypto/tls、crypto/x509、net/url、net/http、os）全部在 go1.26.6 修复。另报 6 个在 golang.org/x/net v0.39.0，代码可达路径未命中。
- **建议**：升工具链到最新 1.26.x。改一行的事。

---

## E. 死代码（三个 agent 用不同方法得出高度一致的结果）

deadcode 报 13 个不可达函数，其中 11 个在 internal 下。vpntest 里还有一批只写不读的字段与零调用方法。

### [ ] E1 internal/vpn 与 internal/service 的零调用函数

| 符号 | 位置 | 备注 |
|---|---|---|
| SMSCooldown | internal/vpn/classify.go:92 | 循环逻辑：先把冷却秒数拼进错误文本，再用 regex 从文本里取出；且函数体内 MustCompile，每次调用都重编 |
| ValidateTOTPSecret | internal/vpn/totp.go:26 | 死代码且**什么都没校验** —— otp.NewKeyFromURL 只做 url.Parse，从不碰 base32 内容。要么删，要么改成真校验（base32 解码）并接进 config.validate |
| NewClient | internal/vpn/client.go:75 | 所有调用点都用 New(Options) |
| Client.Server 与 Client.Timeouts | internal/vpn/client.go:117,120 | 两个 getter 零引用 |
| Session.Trace 与 Session.QueryConn | internal/vpn/session.go:58,61 | 纯属多余暴露 |
| Service.WaitReady | internal/service/service.go:679 | 自称「用于测试和启动检查」，两件事都没做（测试用的是自己那份 waitState） |
| ListenHost.String | internal/wireguard/bind.go:36 | 无任何调用者 |
| Device.PeerCount | internal/wireguard/device.go:222 | 只有测试用；生产路径用 Stats()。也可考虑真接进 wg-stats（「peer 数 1」是判断客户端有没有接上的好信号） |
| Device.relay 字段 | internal/wireguard/device.go:50 | 只写不读；真正持有 Relay 的是 device.tun.device |

### [ ] E2 cmdWGStats 枚举值没有任何发送方

- **位置**：`internal/service/service.go:41`
- **问题**：既没人发送，dispatch 的 switch 里也没有对应分支 —— 真发出去只会落到 default 的「未知命令」。它看起来像「统计走 actor」，实际 WireGuardStats 绕开 actor 直接读设备。
- **建议**：删掉枚举值，并把「device 由 actor 写、只读查询读」的注释改成「device 指针用 s.mu 保护，绕开 actor」。

### [ ] E3 ipc.CmdPing 的服务端分支是死分支

- **位置**：`internal/ipc/protocol.go:27`、`internal/service/server.go:141`
- **建议**：要么在 CLI 加 njuvpn ping（排查「服务在不在」最便宜的手段），要么删掉常量与分支。留着会让人以为已有探活能力。**我倾向加 ping**。

### [ ] E4 vpntest 里的死代码

| 位置 | 备注 |
|---|---|
| Portal.SetFallback fake.go:98 | 零调用 ⇒ fallback 恒为 nil ⇒ 对应分支不可达 |
| Tunnel.AllowQueryIP fake.go:301 | 零调用（RejectQueryIP 有，恢复的没有） |
| Tunnel.OnUplink fake.go:315 | 零调用 ⇒ 回调分支恒假 |
| recvCh fake.go:264 | 只发不收；WaitRecvStream 反而用 5ms 轮询。**建议改成用 channel 等待** —— recvCh 从死代码变回有用，测试不再依赖时序赌博 |
| Response.Status / Chunks / Delay fake.go:51,54,56 | 无测试构造 ⇒ 分片、延迟、非 200 分支全不可达 |
| TunnelStats 的 Connections/QueryIP/Streams/Downlink 与 Request.Method/Query | 都会写但无人读，对断言贡献为零，还让 Stats() 每次多拷一份 |

### [ ] E5 SetClientFactory 只在测试里用，它遮挡的生产分支零覆盖

- **位置**：`internal/service/service.go:96`（定义）与 :292（被遮挡的生产分支）
- **问题**：四个调用点全在测试里，测试注入的 client **不传 DialAddr** —— 而 server_ip（因校园 DNS 解析不了而必须用的字段）正是靠这条接线生效的。就算这里接错，17 个用例依旧全绿。
- **建议**：改成注入 vpn.DialFunc 或 Options 覆盖，让生产分支的 Server / DialAddr / Proxy 接线进入测试。

---

## F. 简化候选（不改行为）

### [ ] F1 splitFlags 与 joinPositional 用标准库解析循环替掉

- **位置**：`cmd/njuvpn/main.go:227,246`
- **问题**：两个函数各自重新实现了 flag 语法且必须永远一致；目前正确只是因为现有 flag 恰好没有「布尔 flag 紧跟位置参数」的组合。
- **替换**：标准写法（fs.Parse 后取 fs.Arg(0)，用剩余参数继续解析），省约 30 行，顺带获得双横线终止符等正确行为。

### F2 windowsProgram 的 done 通道握手可以整个删掉 —— **已作废（见 B5）**

- **位置**：`internal/service/run_windows.go:16`
- **说明**：为「知道自己起的 IPC 服务端何时退出」引入了一个字段、一次 make、一次 close 和一处永久阻塞点，却既没把启动错误交给 SCM 也没真正结束服务端。与 B1、B2 合并处理后，这两个 bug 变成不可能发生的形状。

### [ ] F3 persistWireGuardField 改成值区段替换

- 与 C2 是同一处改动。

### [ ] F4 statusStore.set 的迁移错误在 6 个调用点里被 5 个丢掉

- **位置**：`internal/service/status.go:68` 与 `service.go:250,556,639,672`
- **问题**：transitions 表加「非法迁移报错」是想当安全网，但一半调用点写成下划线等于 set(...)。真出非法迁移时状态会**静默停在原地**，status 照样给出一个看起来正常的状态。
- **说明**：agent 逐条走完全部调用点与迁移表，**当前流程里没有可达的非法迁移** —— 这是降低维护面，不是修 bug。
- **建议**：让 set 不返回错误、非法迁移就地更新并记日志；或者反过来把所有调用点收敛到统一处理，不要留下被忽略的返回值。

### [ ] F5 两处语义不同的信号处理合并成一个 helper

- **位置**：`internal/service/server.go:256`、`cmd/njuvpn/main.go:460`
- 与 C16 是同一处改动。

### [ ] F6 合并 ProtocolError 与 portalErr

- **位置**：`internal/vpn/errors.go:84`、`internal/vpn/portal.go:20`
- **说明**：两者都是 Step 加 Reason，Error() 同构，纯历史残留。省约 12 行。

### [ ] F7 UserMessage 改成类型自己的方法

- **位置**：`internal/vpn/classify.go:108`
- **问题**：现在是「AuthRequiredError.Error() 拼出 Kind 加 State，然后 UserMessage 用 LastIndex 拆回来」—— 字符串手术。
- **建议**：给 AuthRequiredError 加 UserText() 直接返回面向用户的句子，字符串手术与脆弱性一起消失。

### [ ] F8 setDevice 与 currentDevice 换成 atomic.Pointer

- **位置**：`internal/service/service.go:178,186`
- **说明**：只做指针交换和读取，不需要互斥量，也少一层「这个字段谁在锁里访问」的心智负担。省约 12 行。

### [ ] F9 parse.go 的正则缓存不必用 sync.Map

- **位置**：`internal/vpn/parse.go:27`
- **说明**：标签是固定的小集合（十来个），每次 tagValue 要做一次 map 查找加一次接口断言。换成包级 var 后 init 期编译一次。这是最热的解析路径。

### [ ] F10 splitPacket 里的两处上限校验都不可达

- **位置**：`internal/wireguard/relay.go:123,160`
- **算术证明**：total 来自 uint16，最大 65535，而 maxFrameBuffer 是 65536，所以 total 大于 maxFrameBuffer 恒假；deliver 的循环退出时 frameBuf 最多 65534 字节，另一处也恒假。
- **建议**：留一处，并把名字改成真实语义（例如 maxIPv4Packet 取 65535），免得后来者以为这里有独立的防爆内存闸门。

### [ ] F11 countDrop 把 5 种丢包原因混成一个数字

- **位置**：`internal/wireguard/relay.go:171`
- **问题**：队列满、下行地址不匹配、上行非 IPv4、上行源地址不对、读缓冲装不下 —— 全走同一个计数器与同一句文案。用户最容易犯的错（Clash 的 ip 与 wireguard.peer_address 不一致）只会表现为「隧道是 up 的，但一个包都过不去」，日志里没有任何线索。
- **建议**：几个 atomic 字段加每种原因首条日志（或各自限速），约 +15 行。

### [ ] F12 三个查询方法各跑一遍 IpcGet

- **位置**：`internal/wireguard/device.go:186,200,222`
- **问题**：Stats、PeerCount、ListenPort 各自把整份 UAPI 配置序列化一次；Stats 里用指向切片元素的指针，靠「同一 peer 的字段总在下一个 append 之前写完」才成立 —— 今天是对的，但挪一行就会静默丢数据。
- **建议**：收口成一次解析（用索引而非指针）。几行改动。

### [ ] F13 IPC 响应行：FormatResponse 不检查长度上限、ParseResponse 硬切列号

- **位置**：`internal/ipc/protocol.go:74,85`
- **问题**：「2000 x」会被解析成 code=200、msg="1 x"；超长消息只会得到「报文行超过长度上限」这种与真实错误无关的提示。
- **建议**：FormatResponse 按上限截断并在尾部加省略号；ParseResponse 改成按第一个空格切分加三位数校验。

### [ ] F14 helpers.go 的 utlsTunnelConn 包装类型可以直接删

- **位置**：`internal/vpn/helpers.go`
- **说明**：隧道方向不需要实现 sessionIDSource，这个类型纯粹为对称性存在。

### [ ] F15 Mapper 只修 TCP 与 UDP，其他带伪头校验和的协议会被静默改坏

- **位置**：`internal/wireguard/mapping.go:87`
- **说明**：SCTP、DCCP 等同样把地址纳入校验和。校园网场景里基本不存在，所以更划算的是给未知协议打一条限速日志，而不是白名单化（白名单会误伤 ICMP 等无伪头协议）。

### [ ] F16 Read 里 len(bufs) == 0 的分支不可达

- 设备侧 batchSize 恒为 1，至少会传一个 buffer。与 F10 一并清理。

---

## G. 单用户假设下不做（原按「多用户 / 敌对本机」写的加固）

> 这个工具是你的个人客户端：机器上只有你一个用户，服务进程与 CLI 都由你本人启动，
> 没有第二个账户，也没有需要用这条 IPC 通道去攻击的人。下面几条防的都是这种不存在的
> 攻击者，默认不做 —— 同意就回「G 全部不做」。

### [ ] G1 配置文件权限校验（原 D2）

- **位置**：`internal/config/config.go:135`（`checkPermissions`）
- **现状**：Unix 分支要求 0600 否则拒绝启动；Windows 分支直接 return nil。
- **为什么不做**：防的是「同机其他用户读到账号口令与 TOTP 密钥」，而机器上唯一的用户就是你。这条还会咬到自己 —— 以 `User=` 跑的服务读 root 拥有的 0600 文件会直接启动失败。
- **顺带的收益**：A1 修默认路径时把 Windows 默认值改到用户目录（`%LOCALAPPDATA%` 下的 njuvpn 目录），比 ProgramData 更贴合 B3 的身份模型，也就不需要再补 ACL 校验。
- **建议**：删掉 `checkPermissions` 与调用点。

### [ ] G2 IPC 对端校验 VerifyPeer（原 D3）

- **位置**：`internal/ipc/listen_windows.go:67`、`internal/ipc/listen_unix.go:107`、调用点 `cmd/njuvpn/main.go:219`
- **现状**：Windows 侧只检查端点前缀（等于空实现），Unix 侧检查套接字模式与属主。
- **为什么不做**：抢占管道名或换掉套接字，都需要同机的第二个用户或敌意进程。Unix 侧那点校验在 B3a 之后也失去意义（`$XDG_RUNTIME_DIR` 天然 0700）。
- **建议**：删掉 `VerifyPeer` 的两份实现与调用点，`auth` 少一次往返。

### [ ] G3 验证码经 argv 的可见性（原 D5）

- **位置**：`cmd/njuvpn/main.go:209`
- **现状**：不带参数时交互式提示输入（安全路径已经实现），但 usage 与 HANDOFF 推荐带参数写法。
- **为什么不做**：`ps` 里看到别人进程的命令行，前提是机器上有别人。
- **建议**：不改代码。usage 里两行顺序调换零成本，算可选。

### [ ] G4 IPC 连接槽位上限（原 D7）

- **位置**：`internal/service/server.go:27`（`maxConns = 32`）与 :81
- **现状**：连接建立即占一个槽位，占满后新连接被拒。占满需要同机敌意进程一直保持连接。
- **为什么不做**：正常使用下 CLI 都是短命进程，连接随进程退出消失。
- **建议**：删掉 `sem` / `maxConns`（约 10 行）。它挡不住真正的风险，却新增一条「服务活着但谁也连不上」的失败模式。

### [ ] G5 命名管道的自定义 DACL（建议保留）

- **位置**：`internal/ipc/listen_windows.go:33`（`currentUserSDDL`）
- **现状**：显式指定「当前用户 + SYSTEM + 管理员」可访问。
- **判断**：这条与前四条不同 —— 删掉后依赖 Windows 默认 DACL，结果差别不大；但它只有 4 行、无状态、不会咬人。**建议留着，只把注释改成「只让当前用户与管理员访问」，去掉防多用户攻击的口气。**
- **说明**：B3 之后服务以登录用户运行，这个 DACL 与运行账户自洽。

## H. 文档漂移（已核实）

起因：你说仓库里的文档可能过时。我据此把这几处与代码逐条对了一遍，结论如下。

### H1 NOTES.md 已删除（本次整理）

它是迁移期的过程记录，多处已不成立（`internal/vpn/login.go` 不存在、`TunRelay` 已改名、
「待实现」清单大部分完成）。其中仍然有用的部分已并入 HANDOFF.md：
构建命令进了 §2.2，依赖版本在 `go.mod` 的注释里，已知约束在 §5 与 §2.0。
它那句「服务端侧账号状态机异常、需要人工重置」的推断也不再保留 —— 后续实测表明
真实原因是配额与冷却（HANDOFF §2.0）。全文留在 git 历史里。

### H2 HANDOFF.md 已按本次整理修正

- 行数过时（3300 → 实测 6274 生产 / 3567 测试）：**已改**。
- §2.1 的 `sudo ./njuvpn service install` 与 B5 / G1 冲突：**已改为注解**，指向第 10 节。
- §9 表格里 `internal/ipc` 的「端点权限校验、连接数上限」：**已注明**这两项按 G2 / G4 删除。
- §1 引用已删除的 `build_assets/...` 测试包：**已改写**成「那次对照后来做了」。
- §1 的「容器占位」假设：**已标注未证实**，并写明后来官方客户端在同一服务器上也能建隧道。

### H3 我此前说错的两处（已改）

- 我说过「kardianos 只会写 `/etc/systemd/system`」—— **错**。它支持 `UserService: true`，会写 `~/.config/systemd/user/` 并调 `systemctl --user`（`service_systemd_linux.go:76,143,306`）。
- 我说过 Linux「unit 里加 `User=` / `Group=`」—— 模板里只有 `User={{UserName}}`，**没有 Group**（`service_systemd_linux.go:338`）。

### H4 仍然准确的文档说法（抽查）

- 「服务进程退出时无条件登出，相当于 atexit」：`cmdRun` 的 `defer svc.Close()` 确实如此。
- 「服务进程不需要 root」：与 B3 的核实一致。
- 依赖表、MTU 取值（隧道 1400 / WireGuard 1320）、`Is_enable_mult_client=0` 的单客户端限制，都与代码或配置样例一致。

---

## 附：本次审查的方法与已核实无问题的点

**方法**：四个子 agent 分区只读审查（协议层 / 服务与 CLI / 承载与 IPC / 拨号与配置），
各自跑 go build、go vet、staticcheck、deadcode、go test -race 与全仓库搜索；
我另跑 govulncheck，并对 A1 至 A5、C1、C18 逐条读源码或做算术验证。
四个 agent 都确认工作区未被改动（git status 干净）。

**已核实无问题**（避免以后重复怀疑）：

- stripCDATA 的下标安全（前后缀不可能在 12 字节内同时成立）
- sessionIDToken 与 streamToken 的长度校验完整，无切片越界
- queryIP 的 owned 标志保证每条错误路径都关连接；reply[0] 与 reply[4:8] 都在长度判定之后
- openStream 的 deadline 设在第一次 Write **之前**（uTLS 是懒握手），数据阶段清除
- 校验和增量更新（RFC 1624）数学正确：100 万随机样本与全量重算 0 次不一致；分片非首片只修 IP 头正确；UDP 原校验和为 0 时不动正确
- Close 与 logout 的幂等成立；ctx 已取消时仍会发出登出
- 二次验证续用同一会话时不会登出（有两条回归测试钉住）
- 代次（gen）加状态双检查真的挡住了旧隧道协程
- SOCKS5 握手的分支完整（认证方法协商、255 长度检查、ATYP 0x03 的变长跳过）
- 代理地址无法注入 CRLF（配置层已挡控制字符与 host:port 写法）
- validateListenHost 与 wireguard.ParseListenHost 的取值集合逐项一致
- 关闭期无死锁；自定义 Bind 的端点类型与批量语义自洽
- 日志里没有密码、密文、TWFID 明文
