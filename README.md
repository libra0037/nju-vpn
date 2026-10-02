# nju-vpn

南京大学校园网 VPN 的第三方客户端。支持 Windows 与 Linux，理论上支持 macOS 但未实测。

服务进程把校园网隧道拼接到 WireGuard 隧道上，Clash、sing-box 之类的程序都能以 WireGuard 对端的身份接入，从而访问校内资源。

> 实测结论、设计取舍与踩过的坑见 [HANDOFF.md](HANDOFF.md)。

## 特性

- **不需管理员权限**：承载层是用户态 WireGuard，不强制安装 TUN 驱动或虚拟网卡，装了 Clash 就能用。
- **一条命令启动**：`njuvpn start` 会按需拉起服务进程，不必配置为系统服务，只在登录密码或短信验证码必需时才向用户索要。
- **二次验证可免**：把本机绑成授信终端之后，登录不再需要短信验证码。
- **同机可跑多个实例**：每份配置文件各自一个实例，端点与日志互不打扰。

## 安装

从 [Releases](../../releases) 下载对应平台的二进制，改名为 `njuvpn`（Windows 下是`njuvpn.exe`）后直接运行，没有别的依赖。

也可以自己编译：

```bash
go build -o njuvpn ./cmd/njuvpn
```

## 使用

### 1. 准备配置

把配置模板文件 `config.example.yaml` 复制后填写。

| 平台 | 配置文件默认读取路径 |
|---|---|
| Linux | `$XDG_CONFIG_HOME/njuvpn/config.yaml`（不存在时回退到 `~/.config/njuvpn/config.yaml`） |
| Windows | `%LOCALAPPDATA%\njuvpn\config.yaml` |

模板里的多数字段已为南大 VPN 填好，需要自己填学工号 `username`，`password` 留空则需要在每次登录 VPN 时手动输入登录密码。

- 通常不需填写 `server_ip`，除非本机 DNS 解析不了 `server`。
- 通常不需填写 `proxy`，除非本机到服务端需要另择出口。该出口必须是稳定的单一地址。
- `device_id` 用于标识授信终端，由程序自动生成并写回配置。删掉或换掉等于换了一台设备，下次登录会需要短信验证码。
- 首次生成身份需要配置文件所在目录可写；Unix 下目录须属于当前用户且不允许其他用户写入。写回失败会停止启动。
- 配置文件里有凭据，服务进程启动时会把它收紧到 `0600`。

### 2. 命令行

```bash
njuvpn start [--trust]  建立隧道（加 --trust 时在这次登录成功后把本机绑成授信终端）
njuvpn status           查看状态（加 -check 时隧道不在 up 就以非 0 退出，便于脚本巡检）
njuvpn resources        打印当前登录会话的校内资源列表（不启动服务进程、登录或重新拉取资源表）
njuvpn stop             断开隧道（本来就没在跑也按成功处理）
njuvpn restart          重启服务进程（改完配置后用它）
njuvpn trust            把本机绑成授信终端（之后登录免二次验证）
njuvpn untrust [--all]  解除本机授信；--all 解除该账号下全部授信终端
njuvpn version          查看版本
```

所有命令都认 `-config <路径>`。

`start` 支持管道输入，便于脚本：`printf '%s\n%s\n' "$PASSWORD" "$CODE" | njuvpn start`。

### 3. WireGuard 对端接入

对端可以是任意支持 WireGuard 的程序（Clash、sing-box、内核 WireGuard、……）。主要步骤是生成对端密钥对、配置对端节点、配置路由规则：

1. 生成对端的密钥对，把**对端公钥**填进配置的 `wireguard.peer_public_key`。Linux 上也可用 `wg`，见下文。
   （承载层在服务进程启动时就建好了，之后若要改这个键需 `njuvpn restart`，会重新登录一次 VPN。）

   ```bash
   python3 - <<'EOF'
   import base64
   from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
   from cryptography.hazmat.primitives import serialization
   k = X25519PrivateKey.generate()
   b64 = lambda b: base64.b64encode(b).decode()
   print("对端私钥 → Clash 的 private-key     :", b64(k.private_bytes(
       serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())))
   print("对端公钥 → njuvpn 的 peer_public_key:", b64(k.public_key().public_bytes(
       serialization.Encoding.Raw, serialization.PublicFormat.Raw)))
   EOF
   ```

2. 启动 `njuvpn start`。首次启动会生成承载层私钥并写回配置文件，日志文件里会有 `WireGuard 承载层公钥: ...`——**承载层公钥是启动之后才有的**。

3. 配置 WireGuard 对端节点。以下对端配置仅为示例，IP 和端口必须与配置文件里的一致。

   **Clash Verge**：添加一个 WireGuard 节点即可：

   ```yaml
   - name: nju-vpn
     type: wireguard
     server: 127.0.0.1
     port: 51820
     ip: 10.66.66.2
     private-key: <对端私钥>
     public-key: <承载层公钥>
     allowed-ips: ["172.16.0.0/12"]
     udp: true
     mtu: 1400
   ```

   **Linux 内核 WireGuard（内核版本≥5.6，需 `sudo`）**：首先安装工具并生成密钥对：

   ```bash
   sudo apt install wireguard-tools
   wg genkey | sudo tee /etc/wireguard/client.key | wg pubkey   # 输出的就是对端公钥
   sudo chmod 600 /etc/wireguard/client.key
   ```

   然后写 `/etc/wireguard/njuvpn.conf`（`chmod 600`）并起接口：

   ```ini
   [Interface]
   PrivateKey = <对端私钥>
   Address = 10.66.66.2/32
   MTU = 1400

   [Peer]
   PublicKey = <承载层公钥>
   Endpoint = 127.0.0.1:51820
   AllowedIPs = 172.16.0.0/12
   PersistentKeepalive = 25
   ```

   接口上只留这一个地址：多写一个（例如并存两个实例时）内核会拿另一个当源地址，包在 WireGuard 层被静默丢弃，表现得像隧道没通。

   ```bash
   sudo wg-quick up njuvpn     # 起隧道
   sudo wg-quick down njuvpn   # 收工
   sudo wg show                # 看握手与流量
   ```

   校外资源**不能**通过校园网隧道访问（协议上的禁止，非本程序的有意设计），必须走直连，因此两份配置的 `allowed-ips` / `AllowedIPs` 不建议直接写 `0.0.0.0/0` ，建议按自己的实际需求收窄到 `njuvpn resources` 之内。

4. 配置路由。Clash 需手动设置代理规则，`wg-quick` 会自动设置系统路由表。仅让校内资源走校园网 VPN，避免影响到校外资源的访问。

### 多实例与开机自启

同一台机器上跑多个实例：每实例一份配置文件，各自派生自己的 IPC 端点与日志名，再各配一个不同的 `wireguard.listen_port` 即可。`njuvpn status` 会报出实例身份（PID、账号、配置路径与端点），用来确认命令打在了哪个实例上。

不内置开机自启：Windows 用任务计划程序建一个「登录时启动」的任务（程序填 `njuvpn.exe`，参数填 `run -config <配置路径>`）；Linux 写一个 systemd user unit。

## 许可

Apache License 2.0，见 [LICENSE](LICENSE)。
