# nju-vpn

南京大学校园网 VPN 的第三方客户端。支持 Windows 与 Linux，理论上支持 macOS 但未实测。

服务进程把校园网隧道拼接到 WireGuard 隧道上，任何支持 WireGuard 节点的客户端（Clash、sing-box 等）都能通过它访问校内资源。

> 实测结论、设计取舍与踩过的坑见 [HANDOFF.md](HANDOFF.md)。

## 特性

- **不需管理员权限**：承载层是用户态 WireGuard，不强制安装 TUN 驱动或虚拟网卡，装了 Clash 就能用。
- **一条命令启动**：`njuvpn start` 会按需拉起服务进程并建立隧道，不必配置为系统服务，口令与短信验证码只在需要时问你要。
- **同机可跑多个实例**：每份配置文件各自一个实例，端点与日志互不打扰。
- **二次验证可免**：登录要短信验证码，把本机绑成授信终端（`njuvpn trust`）之后，同一台设备再登录不必再要码。

## 安装

从 [Releases](../../releases) 下载对应平台的二进制，改名为 `njuvpn`（Windows 下是`njuvpn.exe`）后直接运行，没有别的依赖。Windows 与 Linux 的产物都做过端到端实测；macOS 的产物只保证能编译。

也可以自己编译：

```
go build -o njuvpn ./cmd/njuvpn
```

## 使用

### 1. 准备配置

把 `config.example.yaml` 复制到默认路径后填写：

| 平台 | 路径 |
|---|---|
| Linux | `$XDG_CONFIG_HOME/njuvpn/config.yaml`（未设置时 `~/.config/njuvpn/config.yaml`） |
| Windows | `%LOCALAPPDATA%\njuvpn\config.yaml` |

模板里 `server` 已经填好，只需要填账号（`username`）；本机 DNS 解析不了 `vpn.nju.edu.cn` 时再填 `server_ip`。

- `password` 留空就每次启动时问你要，只留在服务进程内存里。
- 一般直连即可；本机到服务端要另择出口时再写 `proxy`（服务端把会话绑到源 IP，代理的出口必须是稳定的单一地址）。
- 首次启动会生成 `device_id` 并写回配置：授信终端绑的就是它，删掉或换掉等于换了一台设备，登录又要走一次二次验证。
- 首次启动会自动生成 WireGuard 私钥并写回配置文件，启动日志里打印服务端公钥。
- 配置文件里有凭据，服务进程启动时会把它收紧到 `0600`。

### 2. 建立隧道

```
njuvpn start            建立隧道（必要时拉起服务进程，需要时提示输入口令与验证码）
njuvpn status           查看状态（加 -check 时隧道不在 up 就以非 0 退出，便于脚本巡检）
njuvpn stop             断开隧道（本来就没在跑也按成功处理）
njuvpn restart          重启服务进程（改完配置后用它）
njuvpn trust            把本机绑成授信终端（之后登录免二次验证）
njuvpn untrust [--all]  解除本机授信；--all 解除该账号下全部授信终端
njuvpn version          查看版本
```

所有命令都认 `-config <路径>`。

`start` 支持管道输入，便于脚本：`printf '%s\n%s\n' "$PASSWORD" "$CODE" | njuvpn start`。

### 3. 客户端接入

客户端是任意支持 WireGuard 的程序。两边的公钥是分开的，按这个顺序来：

1. 客户端先生成自己的密钥对（Clash Verge 会自动生成；内核 WireGuard 用 `wg genkey | wg pubkey`），把**客户端公钥**填进配置的 `wireguard.peer_public_key`。
   （承载层在服务进程启动时就建好了，之后改这个键要 `njuvpn restart`，重启会重新登录一次。）
2. 启动 `njuvpn start`。首次启动会生成承载层私钥并写回配置文件，日志里有一行 `WireGuard 服务端公钥: ...`——**服务端公钥是启动之后才有的**。
3. 把**服务端公钥**填进客户端。这一步不影响服务进程，不必重启。

**Clash Verge**：添加一个 WireGuard 节点即可（客户端私钥由它自己生成，把对应的公钥填进 `wireguard.peer_public_key`；`ip` 必须与服务端的 `peer_address` 一致，通常是 10.66.66.2）：

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

**Linux 内核 WireGuard（内核版本≥5.6，需 `sudo`）**：装工具、生成密钥对，把公钥填进 `wireguard.peer_public_key`：

```
sudo apt install wireguard-tools
wg genkey | sudo tee /etc/wireguard/client.key | wg pubkey   # 输出的就是客户端公钥
sudo chmod 600 /etc/wireguard/client.key
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

接口上只留这一个地址：多写一个（例如并存两个实例时）内核会拿另一个当源地址，包在 WireGuard 层被静默丢弃，表现得像隧道没通。

```
sudo wg-quick up njuvpn     # 起隧道
sudo wg-quick down njuvpn   # 收工
sudo wg show                # 看握手与流量
```

两种客户端的 `allowed-ips` / `AllowedIPs` 都写 `0.0.0.0/0` 时，整台机器的流量都走校园网出口；只想让校内地址走隧道，就把它们收窄到校内网段。

### 多实例与开机自启

同一台机器上跑多个实例：每实例一份配置文件，各自派生自己的 IPC 端点与日志名，再各配一个不同的 `wireguard.listen_port` 即可。`njuvpn status` 会报出实例身份（PID、账号、配置路径与端点），用来确认命令打在了哪个实例上。

不内置开机自启：Windows 用任务计划程序建一个「登录时启动」的任务（程序填 `njuvpn.exe`，参数填 `run -config <配置路径>`）；Linux 写一个 systemd user unit。

## 许可

Apache License 2.0，见 [LICENSE](LICENSE)。
