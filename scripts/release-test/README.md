# 发布前测试包

所有实机脚本都要求先设置 `NJUVPN_TEST_TARGET_IP`，不要把实际机器地址写入源码。以下 `192.0.2.1` 是文档保留地址，运行时须替换为实际校内目标；目标应在直连时不可达、经本次 VPN 可达。Linux 使用 `export NJUVPN_TEST_TARGET_IP=192.0.2.1`，Windows 使用 `$env:NJUVPN_TEST_TARGET_IP = '192.0.2.1'`。执行 setup／cleanup 的 sudo 命令时增加 `--preserve-env=NJUVPN_TEST_TARGET_IP`。离线用例不需要实际目标、账号或网络服务。

本包只含候选程序、独立测试程序、公开配置样例和测试脚本，不含账号或密钥。`BUILD.txt` 和 `SHA256SUMS` 标识被测候选版本。测试结果中的 FAIL 和 SKIP 均需检查，不能只看脚本最终退出码。

离线用例验证真实 WireGuard 握手与双向传包、命令拉起候选服务进程、IPC 身份校验、TLS 指纹、资源表上限、分片、并发与关闭路径，使用临时文件和回环服务，不登录真实 VPN。需要机器没有禁用回环通信；不需要安装 Go 或管理员权限。

Linux x64：解压后运行 `bash run-linux.sh`。包内同时包含普通与 race 测试程序；race 程序依赖 glibc。回传 `results-offline-*` 目录。

Windows 10 x64：解压到本地磁盘，打开普通 PowerShell，进入解压目录，运行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\run-windows.ps1
```

回传脚本打印的 `results-offline-*.zip`。本包没有 Windows race 程序；Windows race 和另外四个支持目标的原生测试须单独验证。

实机配置请放在测试包之外，Linux 使用 `/绝对路径/测试目录/config.yaml`，Windows 建议放到 `$env:LOCALAPPDATA\njuvpn-test\config.yaml`。不要回传配置、密钥目录或服务进程日志。允许仅在配置里填写口令，也可交互输入。沿用已授信的 device_id 时仍可能要求短信；脚本不授信或解除授信。

Linux 对端准备：运行 `bash prepare-linux-peer.sh /绝对路径/测试目录/config.yaml`，再按脚本输出执行 sudo 命令，重配专用 `wgtest`，MTU 1400。独立路由表 61121、优先级 21121 只将该目标的 HTTP 18080、UDP 18081 和 ICMP 送入测试接口，保留 SSH 等控制连接原路由；已有同号规则或表时拒绝覆盖。随后运行 `bash live-linux.sh /绝对路径/测试目录/config.yaml`，排障时可用第二个参数指定诊断二进制。实机结果摘要在 `results-live-*`，完整命令输出在配置旁的 `private-*`，只回传摘要。

Windows 对端准备：可复制已有可用配置到独立测试目录，沿用现有对端密钥和 device_id；也可复制公开配置样例后填写账号，运行 `test-helper.exe new-peer -out <私有目录>` 得到公钥和 `peer.key` 私钥文件，把公钥填入 `wireguard.peer_public_key`。`njuvpn.exe restart -config <测试配置>` 会初始化承载私钥，然后 `test-helper.exe info -config <测试配置>` 打印承载公钥。为 mihomo 增加专用测试 WireGuard 节点，使用对端私钥、承载公钥、配置中的端口和 peer_address，MTU 1400，allowed-ips 包含测试目标 `192.0.2.1/32`，`udp: true`。只将该测试目标路由到此节点。

完成离线测试后，停止其他使用同账号的 VPN，会与 Linux 端顺序运行实机测试：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\live-windows.ps1 -ConfigPath "$env:LOCALAPPDATA\njuvpn-test\config.yaml" -ProxyName "nju-vpn-test" -ApiUrl "http://127.0.0.1:9097"
```

API secret 由脚本在本机询问，留空表示无 secret，不写日志。脚本只读取 mihomo API 和测试指定节点，不改代理选择。API 调用依据 [mihomo 官方文档](https://wiki.metacubex.one/api/)。实机测试服务在你有权访问的校内机器启动，HTTP 端口 `18080`、UDP 端口 `18081`。使用 `python3 target-server.py --bind <实际 IPv4 地址>`；默认仅监听回环。

上传诊断只回传运行库的收发计数；写入请求流不代表目标已经收到。维护者目标记录实际收到的正文长度及首末进度时间，以随机 `run_id` 对照；超时也保留部分计数，不记录正文、请求头或地址。

区分 HTTP 客户端影响时，给同一 live 命令增加 `-UploadClient Go`：仅把 1 MiB 上传换为 Go HTTP，经同一 mihomo HTTP 入口及既有 WireGuard 规则；下载、API、UDP 仍按原流程。该入口要求无凭据的 IPv4 回环 HTTP 代理，忽略环境代理，保留已知长度、二进制正文、`Expect: 100-continue`、90 秒期限和独立摘要。Go 结果写入 `upload-go-summary.json`，还须通过 API 观察到上传新增连接包含指定 WireGuard 节点，排除此前下载连接。观察失败也终止并等待子进程。与默认 `-UploadClient DotNet` 顺序对照；每轮仍单独登录，成功只能缩小客户端等差异，不能仅凭几轮通过排除其他层。

检查既有失败日志时，在原包目录运行 `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\collect-logs-windows.ps1 -ConfigPath "实际测试配置路径"`，回传 `results-log-*.zip`。它只读取该配置的当前服务进程日志与最多两份备份，不建立网络连接或改变 VPN 状态；每份最多 4 MiB、每行最多 8 KiB，保留最近 256 个固定事件的 UTC 时间、进程号、原因类别及累计值。原文、路径、账号、密钥和异常正文不会进入摘要。日志目录及结果目录均限 256 项。附带的最近四个结果目录时间仅供粗略关联；轮转、限速、丢弃旧事件及清理时的断开均需考虑，缺少记录不能证明没有发生丢包。

排查 mihomo 之外的路径时，顺序运行 `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\direct-windows.ps1 -ConfigPath "$env:LOCALAPPDATA\njuvpn-test\config.yaml"`。工具自动在配置旁创建新的 `private-direct-*`：复制账号、设备标识、出站代理和 TLS 策略，只替换测试对端公钥及回环端口，原文件保持不变。直接对端使用 wireguard-go 的内存 TUN 与用户态网络栈，不要求管理员权限、网卡、系统路由或 mihomo API；MTU 1400，仅发往上述测试目标。回传 `results-direct-*.zip`，私有配置、密钥和日志不回传。健康检查、UDP 的单请求期限为 30 秒，下载、上传为 90 秒；记录期限、TCP 建连、首字节、总耗时、实际读取长度及固定错误类别。HTTP 客户端是 Go，成功不能单独证明 mihomo 或 .NET 中的哪一层有错，须和同机 live 结果及目标关闭记录对照。

维护者检查直接对端使用 `bash scripts/check-direct-peer.sh`；Go 与静态工具版本取仓库工具链，声明范围为 Linux/amd64、Windows/amd64、无构建标签。它是独立测试模块，新增的 gVisor 网络栈固定为现有 wireguard-go 所声明的版本，不进入产品依赖或发布程序。

Windows 的分片／ICMP 实机验证使用 `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\direct-windows.ps1 -ConfigPath "实际测试配置路径" -PacketChecks`，回传 `results-packets-*.zip`。它使用独立用户态 WireGuard 对端，记录 2000／4000 字节 UDP 的实际 IPv4 首末分片及包长，目标以固定 SHA-256 确认重组内容；ICMP 发送 1372 字节正文、DF、总 IP 长度 1400 并验证响应。大 UDP 只验证上行分片，目标回传小摘要，避免把目标下行 MTU 的差异混入上行判据。

短时断线验证使用 `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\resilience-windows.ps1 -ConfigPath "实际测试配置路径"`，回传 `results-resilience-*.zip`。原测试配置需已初始化身份并在本机填写 password；脚本复制到新的私有实例，出站经过受控回环 CONNECT 转发后沿用原 proxy 或直连方式。验证短暂断线恢复、静默约 45 秒后的心跳判死及恢复、持续拒绝连接耗尽重连预算、手动重新 start、重连期间 stop 及停止后不可达；主流程期限 5 分钟，收尾另设 15 秒期限，不运行授信／解除授信。原配置保持不变，结束时等待独立服务、对端与代理退出；系统网卡和 SSH 路由沿用原设置。Linux 可调用 `test-peer resilience -config <原配置> -binary <njuvpn 程序> -out <新的私有目录> -result <新的公开 JSON> -run-id <32位随机标识>` 执行同一工具。

维护者在仓库中用 `python3 scripts/release-test/target-server-test.py -v` 检查目标期限与 HEAD，用 `python3 scripts/release-test/target-ip-test.py -v` 和 `target-test.ps1` 检查目标输入边界，用 Windows PowerShell 5.1 执行 `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\release-test\live-windows-test.ps1` 检查异步传输期限、取消及脱敏错误；增加 `-PeerToolPath` 并指定已构建的 `test-peer.exe`，还会检查真实 Go 上传入口的 200/502 判据和带空格的中文结果路径。`collect-logs-windows-test.ps1 -PeerToolPath <同一工具>` 检查只读日志选择、固定分类、脱敏及实际 ZIP 内容。这些用例只使用回环服务或临时文件，不登录 VPN。CI 在 Linux/amd64（Python 3.12）与 Windows/amd64 上分别执行，Windows 步骤构建并传入工具路径。

本包通过不表示已完成全部发布验证；还需核对真实资源列表完整性、控制面与承载链路、下载和上传校验、UDP、MTU、分片以及断开后的不可达。普通请求等待上限 30 秒，大文件传输 90 秒；目标端总期限 60 秒、单次读写停滞上限 20 秒。服务器公网出站带宽为 2 Mbit/s，仅 8 MiB 正文就需约 33.6 秒，另留协议开销和一次临时鉴权重试预算；不重试或缩小测试载荷。空闲 50 秒后检查状态，覆盖心跳判死期限。实机脚本结束时断开 VPN 并请求该测试服务退出；Linux 用 `sudo --preserve-env=NJUVPN_TEST_TARGET_IP bash cleanup-linux-peer.sh` 删除测试路由与接口，Windows 专用节点与规则由你移除。
