# nju-vpn

南京大学校园网 VPN 的第三方客户端。用 Go 写，Windows 与 Linux 都能跑。

服务进程把校园网隧道接到本机的 WireGuard 端口上，任何带用户态 WireGuard
实现的客户端（Clash、sing-box 等）都可以通过它访问校内资源。

> 协议细节、实测结论与排查记录见 [HANDOFF.md](HANDOFF.md)。

## 特性

- **不需要 root，不创建网卡**：承载层是 wireguard-go 的用户态 UDP，隧道出口在内存里完成地址改写。
- **Windows 与 Linux 一致**：服务进程由命令行按需拉起，不必安装成系统服务。
 - **口令可以不落盘**：配置文件里留空时，`njuvpn start` 会提示输入（不回显），
   口令只留在服务进程内存里；配置 TOTP 密钥后，重建隧道也不用人守着。
 - **同机可跑多个实例**：每份配置各自一个实例，端点按配置文件的路径派生，互不打扰。
- **出站可经代理**：连服务端时可走 HTTP / SOCKS5 代理。仅在校外直连不通、
  或需要指定出口时使用；服务端把隧道会话绑定到源 IP，代理的出口必须稳定。
- **会话回收**：进程退出时无条件登出，避免残留会话占住同一账号的名额。

## 安装

从 [Releases](../../releases) 下载对应平台的二进制，改名为 `njuvpn`（Windows 下是
`njuvpn.exe`）后直接运行，没有别的依赖。

```
njuvpn version     确认版本
```

也可以自己编译：

```
go build -o njuvpn ./cmd/njuvpn
```

## 使用

```
 njuvpn start            建立隧道（必要时拉起服务进程；需要时提示输入口令与验证码）
njuvpn status           查看状态
njuvpn stop             断开隧道
njuvpn restart          重启服务进程（改完配置后用它）
njuvpn wg-peer <公钥>    更新 WireGuard 接入公钥（不重建隧道）
njuvpn wg-stats         查看 WireGuard 收发统计
njuvpn probe            直接连服务端做协议探测（不经过服务进程）
```

配置文件放在用户目录下，从 `config.example.yaml` 复制一份填写即可：

| 平台 | 路径 |
|---|---|
| Linux | `~/.config/njuvpn/config.yaml` |
| Windows | `%LOCALAPPDATA%\njuvpn\config.yaml` |

首次启动会自动生成 WireGuard 私钥并写回配置文件，启动日志里打印服务端公钥。

`njuvpn start` 是唯一的交互入口：配置里没写 `password` 时先问口令（不回显），
服务端要求二次验证时再问一次验证码。两者都支持管道输入，便于脚本：

```
printf '%s\n%s\n' "$PASSWORD" "$CODE" | njuvpn start -config ~/.config/njuvpn/config.yaml
```

### 同一台机器上跑多个实例

每人一份配置文件、一个实例时不需要额外设置：IPC 端点按配置文件的路径派生
（同一份配置永远是同一个端点，不同配置互不相干），每人写一个不同的
`wireguard.listen_port` 即可，日志在各配置目录下，名字是 `njuvpn-<配置名>.log`。
`njuvpn status` 与 `ping` 都会报出实例身份（PID、账号、配置文件路径与端点），
同机多实例时用它确认命令打在了哪个实例上。

### 客户端接入（以 Clash 为例）

```yaml
- name: nju-vpn
  type: wireguard
  server: 127.0.0.1
  port: 51820
  ip: 10.66.66.2
  private-key: <客户端私钥>
  public-key: <服务端公钥，启动日志里打印>
  allowed-ips: ["0.0.0.0/0"]
  udp: true
  mtu: 1320
```

`allowed-ips` 必须是 `0.0.0.0/0`（否则默认路由不进隧道），`ip` 必须与服务端的
`peer_address` 一致。

## 许可

WTFPL，见 [LICENSE](LICENSE)。
