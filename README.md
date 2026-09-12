# nju-vpn

南京大学校园网 VPN 的第三方客户端。用 Go 写，Windows 与 Linux 都能跑。

服务进程把校园网隧道接到本机的 WireGuard 端口上，任何带用户态 WireGuard 实现的
客户端（Clash、sing-box 等）都能通过它访问校内资源。

> 协议细节、实测结论与设计取舍见 [HANDOFF.md](HANDOFF.md)。

## 特性

- **不需要管理员权限，不创建网卡**：承载层是用户态 WireGuard，隧道出口就在内存里改地址，
  不必装 TUN 驱动或虚拟网卡，装了 Clash 或 sing-box 就能用。
- **一条命令启动**：`njuvpn start` 会按需拉起服务进程并建立隧道，口令与短信验证码
  只在需要时问你要；口令可以不写进配置文件。
- **Windows 与 Linux 一致**：同一套命令，服务进程由命令行按需拉起，不必装成系统服务。
- **退出时无条件登出**：进程收到信号或被关掉都会先注销服务端会话，不会留下占住
  同一账号名额的残留会话。
- **同机可跑多个实例**：每份配置文件各自一个实例，端点与日志互不打扰。

## 安装

从 [Releases](../../releases) 下载对应平台的二进制，改名为 `njuvpn`（Windows 下是
`njuvpn.exe`）后直接运行，没有别的依赖。Windows 与 Linux 的产物都做过端到端实测；
macOS 的产物只保证能编译。

也可以自己编译：

```
go build -o njuvpn ./cmd/njuvpn
```

## 使用

### 1. 准备配置

把 `config.example.yaml` 复制到默认路径后填写：

| 平台 | 路径 |
|---|---|
| Linux | `~/.config/njuvpn/config.yaml` |
| Windows | `%LOCALAPPDATA%\njuvpn\config.yaml` |

模板里 `server` 已经填好，只需要填账号（`username`）；本机 DNS 解析不了 `vpn.nju.edu.cn` 时再填 `server_ip`。

- `password` 留空就每次启动时问你要，只留在服务进程内存里。
- 一般直连即可；本机到服务端要另择出口时再写 `proxy`（服务端把会话绑到源 IP，
  代理的出口必须是稳定的单一地址）。
- 填了 `totp_secret` 就不必再输短信验证码，服务进程可以无人值守启动。
- 首次启动会自动生成 WireGuard 私钥并写回配置文件，启动日志里打印服务端公钥。
- 配置文件里有凭据，服务进程启动时会把它收紧到 `0600`。

### 2. 建立隧道

```
njuvpn start            建立隧道（必要时拉起服务进程，需要时提示输入口令与验证码）
njuvpn status           查看状态（加 -check 时隧道不在 up 就以非 0 退出，便于脚本巡检）
njuvpn stop             断开隧道（本来就没在跑也按成功处理）
njuvpn restart          重启服务进程（改完配置后用它）
njuvpn version          查看版本
```

另有 `ping`（探活并报出实例身份）、`wg-peer <公钥>`（热更新接入公钥，不重建隧道）、
`wg-stats`（查看收发统计）、`probe`（不经过服务进程的协议探测）四条。

`start` 支持管道输入，便于脚本：`printf '%s\n%s\n' "$PASSWORD" "$CODE" | njuvpn start`。

### 3. 客户端接入

服务进程跑起来之后（`njuvpn start` 会替你拉起它），把客户端公钥交给它——也可以直接写在
配置里的 `wireguard.peer_public_key`：

```
njuvpn wg-peer <客户端公钥>
```

服务端公钥在服务进程的启动日志里：`WireGuard 服务端公钥: ...`。

**Windows · Clash Verge**：把下面这段加进配置的 `proxies` 列表（客户端私钥自己生成，
`ip` 必须与服务端的 `peer_address` 一致，通常是 10.66.66.2）：

```yaml
- name: nju-vpn
  type: wireguard
  server: 127.0.0.1
  port: 51820
  ip: 10.66.66.2
  private-key: <客户端私钥>
  public-key: <服务端公钥>
  allowed-ips: ["0.0.0.0/0"]
  udp: true
  mtu: 1320
```

**Linux · 内核 WireGuard**：先装工具（内核模块自 5.6 起已在树内，`apt install
wireguard-tools` 即可），生成密钥对：

```
wg genkey | sudo tee /etc/wireguard/client.key | wg pubkey   # 输出的就是客户端公钥
sudo chmod 600 /etc/wireguard/client.key
njuvpn wg-peer <上一步输出的公钥>
```

然后写 `/etc/wireguard/njuvpn.conf`（`chmod 600`）并起接口：

```ini
[Interface]
PrivateKey = <客户端私钥>
Address = 10.66.66.2/32
MTU = 1320

[Peer]
PublicKey = <服务端公钥>
Endpoint = 127.0.0.1:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

```
sudo wg-quick up njuvpn     # 起隧道
sudo wg-quick down njuvpn   # 收工
sudo wg show                # 看握手与流量
```

两种客户端的 `allowed-ips` / `AllowedIPs` 都写 `0.0.0.0/0` 时，整台机器的流量都走
校园网出口；只想让校内地址走隧道，就把它们收窄到校内网段。

### 多实例与开机自启

同一台机器上跑多个实例：每人一份配置文件，各自派生自己的 IPC 端点与日志名，再各配一个
不同的 `wireguard.listen_port` 即可。`njuvpn status` 与 `njuvpn ping` 会报出实例身份
（PID、账号、配置路径与端点），用来确认命令打在了哪个实例上。

开机自启不内置：Windows 用任务计划程序建一个「登录时启动」的任务（程序填 `njuvpn.exe`，
参数填 `run -config <配置路径>`）；Linux 写一个 systemd user unit。只是登出 SSH 的话
不需要这些，CLI 拉起的服务进程自成会话，会话结束不会把它带走（细节见
[HANDOFF.md](HANDOFF.md) §5.1）。

## 许可

WTFPL，见 [LICENSE](LICENSE)。
