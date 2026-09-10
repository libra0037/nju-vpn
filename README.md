# nju-vpn

南京大学校园网 VPN 的第三方客户端。用 Go 写，Windows 与 Linux 都能跑。

服务进程把校园网隧道接到本机的 WireGuard 端口上，任何带用户态 WireGuard
实现的客户端（Clash、sing-box 等）都可以通过它访问校内资源。

> 协议细节、实测结论与排查记录见 [HANDOFF.md](HANDOFF.md)。

## 特性

- **不需要 root，不创建网卡**：承载层是 wireguard-go 的用户态 UDP，隧道出口在内存里完成地址改写。
- **Windows 与 Linux 一致**：服务进程由命令行按需拉起，不必安装成系统服务。
- **二次验证**：支持短信验证码；配置 TOTP 密钥后可全自动登录。
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
njuvpn start            建立隧道（必要时自动拉起服务进程）
njuvpn auth <code>      提交短信或 TOTP 验证码
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
