param(
    [Parameter(Mandatory = $true)][string]$ConfigPath,
    [Parameter(Mandatory = $true)][string]$ProxyName,
    [string]$ApiUrl = 'http://127.0.0.1:9097',
    [string]$ProxyUrl = '',
    [ValidateSet('DotNet', 'Go')][string]$UploadClient = 'DotNet'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$OutputEncoding = [Text.Encoding]::UTF8
Set-Location $PSScriptRoot
. (Join-Path $PSScriptRoot 'target.ps1')
$target = Get-TestTarget
$ConfigPath = (Resolve-Path -LiteralPath $ConfigPath).ProviderPath
$binary = Join-Path $PSScriptRoot 'njuvpn.exe'
$helper = Join-Path $PSScriptRoot 'test-helper.exe'
$runId = [Guid]::NewGuid().ToString('N')
$results = Join-Path $PSScriptRoot ('results-live-' + $runId)
$private = Join-Path (Split-Path -Parent $ConfigPath) ('private-live-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $results, $private | Out-Null
$summary = Join-Path $results 'summary.txt'
& $binary version | Out-File -LiteralPath $summary -Encoding utf8
Get-Content -LiteralPath (Join-Path $PSScriptRoot 'BUILD.txt') | Out-File -LiteralPath $summary -Append -Encoding utf8
('binary_sha256=' + (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()) |
    Out-File -LiteralPath $summary -Append -Encoding utf8
('live_script_sha256=' + (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()) |
    Out-File -LiteralPath $summary -Append -Encoding utf8
('run_id=' + $runId) | Out-File -LiteralPath $summary -Append -Encoding utf8
('upload_client=' + $UploadClient) | Out-File -LiteralPath $summary -Append -Encoding utf8
if ($UploadClient -eq 'Go') {
    ('upload_tool_sha256=' + (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'test-peer.exe') -Algorithm SHA256).Hash.ToLowerInvariant()) |
        Out-File -LiteralPath $summary -Append -Encoding utf8
}
$baseUrl = 'http://' + $target + ':18080'
$secret = Read-Host 'mihomo API secret（无则直接回车）' -AsSecureString
Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
public sealed class ReleaseTestUploadProgress {
    public readonly long BytesSent, TotalBytesToSend, BytesReceived, TotalBytesToReceive;
    internal ReleaseTestUploadProgress(UploadProgressChangedEventArgs value) {
        BytesSent = value.BytesSent;
        TotalBytesToSend = value.TotalBytesToSend;
        BytesReceived = value.BytesReceived;
        TotalBytesToReceive = value.TotalBytesToReceive;
    }
}
public class ReleaseTestWebClient : WebClient {
    public const int RequestTimeoutMilliseconds = 30000;
    public const int TransferTimeoutMilliseconds = 90000;
    private readonly int timeoutMilliseconds;
    private readonly object progressLock = new object();
    private ReleaseTestUploadProgress uploadProgress;
    public ReleaseTestWebClient() : this(RequestTimeoutMilliseconds) { }
    public ReleaseTestWebClient(int timeout) {
        if (timeout <= 0) { throw new ArgumentOutOfRangeException("timeout"); }
        timeoutMilliseconds = timeout;
    }
    // 只覆盖通知，不订阅事件：.NET Framework 会因事件订阅改变 UploadData 的分块。
    protected override void OnUploadProgressChanged(UploadProgressChangedEventArgs value) {
        lock (progressLock) {
            if (uploadProgress == null ||
                (value.BytesSent >= uploadProgress.BytesSent && value.BytesReceived >= uploadProgress.BytesReceived)) {
                uploadProgress = new ReleaseTestUploadProgress(value);
            }
        }
        base.OnUploadProgressChanged(value);
    }
    public ReleaseTestUploadProgress GetUploadProgress() {
        lock (progressLock) { return uploadProgress; }
    }
    protected override WebRequest GetWebRequest(Uri address) {
        WebRequest request = base.GetWebRequest(address);
        request.Timeout = timeoutMilliseconds;
        HttpWebRequest http = request as HttpWebRequest;
        if (http != null) { http.ReadWriteTimeout = RequestTimeoutMilliseconds; }
        return request;
    }
    // 异步请求不依赖 WebRequest.Timeout；计时器取消并等待原操作，随后释放注册。
    private async Task<byte[]> CompleteTransfer(Task<byte[]> pending) {
        using (CancellationTokenSource deadline = new CancellationTokenSource(timeoutMilliseconds))
        using (deadline.Token.Register(CancelAsync)) {
            byte[] body;
            try {
                body = await pending.ConfigureAwait(false);
            } catch (Exception error) {
                if (deadline.IsCancellationRequested) { throw new TimeoutException("传输超时", error); }
                throw;
            }
            if (deadline.IsCancellationRequested) { throw new TimeoutException("传输超时"); }
            return body;
        }
    }
    public Task<byte[]> DownloadTransferAsync(Uri address) {
        return CompleteTransfer(DownloadDataTaskAsync(address));
    }
    public Task<byte[]> UploadTransferAsync(Uri address, byte[] body) {
        return CompleteTransfer(UploadDataTaskAsync(address, "POST", body));
    }
    public static byte[] Payload(int size, int modulo) {
        byte[] body = new byte[size];
        for (int i = 0; i < size; i++) { body[i] = (byte)(i % modulo); }
        return body;
    }
}
'@
$api = New-Object ReleaseTestWebClient
$api.Proxy = $null
$api.Encoding = [Text.Encoding]::UTF8
if ($secret.Length -gt 0) {
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
    try {
        $api.Headers['Authorization'] = 'Bearer ' + [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}
function Read-Api([string]$Path) {
    return ($api.DownloadString($ApiUrl.TrimEnd('/') + $Path) | ConvertFrom-Json)
}
function Record([string]$Name) {
    $line = 'PASS ' + $Name
    Write-Host $line
    $line | Out-File -LiteralPath $summary -Append -Encoding utf8
}
function Invoke-Cli([string]$Command) {
    $ErrorActionPreference = 'Continue'
    $output = & $binary $Command -config $ConfigPath 2>&1
    $code = $LASTEXITCODE
    $output | ForEach-Object { "$_" } | Out-File -LiteralPath (Join-Path $private ($Command + '.log')) -Encoding utf8
    $ErrorActionPreference = 'Stop'
    if ($code -ne 0) { throw ('命令失败：' + $Command) }
    Record $Command
}
function Read-Helper([string]$Command) {
    $output = & $helper $Command -config $ConfigPath
    if ($LASTEXITCODE -ne 0) { throw ('测试辅助操作失败：' + $Command) }
    return ($output | ConvertFrom-Json)
}
function New-Payload([int]$Size, [int]$Modulo) {
    return ,([ReleaseTestWebClient]::Payload($Size, $Modulo))
}
function Digest([byte[]]$Body) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($algorithm.ComputeHash($Body)) } finally { $algorithm.Dispose() }
}
function Read-UploadProgress($Client) {
    if ($null -eq $Client) { return $null }
    $progress = $Client.GetUploadProgress()
    if ($null -eq $progress) { return $null }
    # 写入请求流的进展，不等同于 mihomo 转发或目标已接收的字节数。
    return [ordered]@{
        bytes_sent = $progress.BytesSent
        total_bytes_to_send = $progress.TotalBytesToSend
        bytes_received = $progress.BytesReceived
        total_bytes_to_receive = $progress.TotalBytesToReceive
    }
}
function Invoke-GoUpload([string]$ToolPath, [string]$Proxy, [string]$RunId, [string]$ResultPath, [string]$PrivatePath, [ScriptBlock]$ProgressCheck = $null) {
    # 使用 Windows 参数规则保护空格、引号和尾部反斜线；不经过命令解释器。
    $arguments = @('upload-proxy', '-proxy', $Proxy, '-run-id', $RunId, '-result', $ResultPath)
    $quoted = foreach ($argument in $arguments) {
        '"' + (($argument -replace '(\\*)"', '$1$1\"') -replace '(\\+)$', '$1$1') + '"'
    }
    $process = New-Object Diagnostics.Process
    $process.StartInfo.FileName = $ToolPath
    $process.StartInfo.Arguments = $quoted -join ' '
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.CreateNoWindow = $true
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    $process.StartInfo.StandardOutputEncoding = [Text.Encoding]::UTF8
    $process.StartInfo.StandardErrorEncoding = [Text.Encoding]::UTF8
    try { [void]$process.Start() } catch { $process.Dispose(); throw }
    $output = $null
    $errors = $null
    try {
        $output = $process.StandardOutput.ReadToEndAsync()
        $errors = $process.StandardError.ReadToEndAsync()
        while (-not $process.WaitForExit(100)) {
            if ($null -ne $ProgressCheck) { & $ProgressCheck }
        }
        $code = $process.ExitCode
    } finally {
        # API 观察失败时也必须终止并等待子进程，不能把它留到后台继续上传。
        try {
            if (-not $process.HasExited) {
                try { $process.Kill() } catch [InvalidOperationException] { if (-not $process.HasExited) { throw } }
                $process.WaitForExit()
            }
            # 工具仅输出固定类别；异步排空两条流并等待，避免管道背压卡住退出。
            if ($null -ne $output) { $output.GetAwaiter().GetResult() | Out-File -LiteralPath $PrivatePath -Encoding utf8 }
            if ($null -ne $errors) { $errors.GetAwaiter().GetResult() | Out-File -LiteralPath ($PrivatePath + '.stderr') -Encoding utf8 }
        } finally { $process.Dispose() }
    }
    if ($code -ne 0) { throw 'Go 代理上传失败，详见脱敏流量结果' }
    $result = Get-Content -LiteralPath $ResultPath -Raw -Encoding utf8 | ConvertFrom-Json
    if (-not $result.passed -or $result.run_id -ne $RunId -or $result.check.bytes -ne 1048576 -or $result.check.http_status -ne 200) {
        throw 'Go 代理上传结果不符合固定判据'
    }
}
function Has-TestChain($Connections, [string]$Network, [Collections.Generic.HashSet[string]]$ExcludeIds = $null) {
    foreach ($connection in $Connections.connections) {
        if (($null -eq $ExcludeIds -or -not $ExcludeIds.Contains($connection.id)) -and
            $connection.metadata.destinationIP -eq $target -and $connection.metadata.network -eq $Network -and $connection.chains -contains $ProxyName) {
            return $true
        }
    }
    return $false
}
function Read-SafeError([Exception]$Cause) {
    # 只保留运行库类别和数值状态，禁止写 Message、URL、响应正文或地址。
    $types = New-Object 'System.Collections.Generic.List[string]'
    $details = [ordered]@{ error_types = @(); web_status = $null; http_status = $null; socket_error = $null; native_error = $null }
    for ($depth = 0; $null -ne $Cause -and $depth -lt 8; $depth++) {
        $types.Add($Cause.GetType().FullName)
        if ($Cause -is [Net.WebException]) {
            $details.web_status = $Cause.Status.ToString()
            if ($Cause.Response -is [Net.HttpWebResponse]) { $details.http_status = [int]$Cause.Response.StatusCode }
        }
        if ($Cause -is [Net.Sockets.SocketException]) {
            $details.socket_error = $Cause.SocketErrorCode.ToString()
            $details.native_error = $Cause.NativeErrorCode
        }
        $Cause = $Cause.InnerException
    }
    $details.error_types = $types.ToArray()
    $details['chain_truncated'] = $null -ne $Cause
    return $details
}
function Read-Exact($Stream, [int]$Size) {
    $data = New-Object byte[] $Size
    $position = 0
    while ($position -lt $Size) {
        $count = $Stream.Read($data, $position, $Size - $position)
        if ($count -eq 0) { throw 'SOCKS 响应提前结束' }
        $position += $count
    }
    return ,$data
}
function Test-Udp([int]$Port) {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $udp = New-Object System.Net.Sockets.UdpClient
    try {
        $tcp.ReceiveTimeout = 10000
        $tcp.SendTimeout = 10000
        $tcp.Connect('127.0.0.1', $Port)
        $stream = $tcp.GetStream()
        $hello = [byte[]](5, 1, 0)
        $stream.Write($hello, 0, $hello.Length)
        $reply = Read-Exact $stream 2
        if ($reply[0] -ne 5 -or $reply[1] -ne 0) { throw '测试需要本机 SOCKS 入口支持无认证' }
        $associate = [byte[]](5, 3, 0, 1, 0, 0, 0, 0, 0, 0)
        $stream.Write($associate, 0, $associate.Length)
        $reply = Read-Exact $stream 4
        if ($reply[0] -ne 5 -or $reply[1] -ne 0 -or $reply[3] -ne 1) { throw 'UDP 关联未返回 IPv4 中继' }
        $address = Read-Exact $stream 6
        $relay = [Net.IPAddress]::new([byte[]]$address[0..3])
        if ($relay.Equals([Net.IPAddress]::Any)) { $relay = [Net.IPAddress]::Loopback }
        if (-not [Net.IPAddress]::IsLoopback($relay)) { throw 'UDP 中继必须在本机' }
        $relayPort = [int]$address[4] * 256 + [int]$address[5]
        $udp.Client.ReceiveTimeout = [ReleaseTestWebClient]::RequestTimeoutMilliseconds
        $udp.Connect($relay, $relayPort)
        foreach ($size in @(32, 1372)) {
            $payload = New-Payload $size 251
            $packet = [byte[]](0, 0, 0, 1, 114, 212, 82, 245, 70, 161) + $payload
            [void]$udp.Send($packet, $packet.Length)
            $endpoint = New-Object Net.IPEndPoint ([Net.IPAddress]::Any), 0
            $response = $udp.Receive([ref]$endpoint)
            if ($response.Length -ne $size + 10 -or $response[2] -ne 0 -or $response[3] -ne 1) { throw 'UDP 响应布局不正确' }
            if ((Digest ([byte[]]$response[10..($response.Length-1)])) -ne (Digest $payload)) { throw 'UDP 回传内容不一致' }
            Record ('udp-payload-' + $size)
        }
        if (-not (Has-TestChain (Read-Api '/connections') 'udp')) { throw '没有观察到 UDP 经过指定 WireGuard 节点' }
        Record 'udp-wireguard-chain'
    } finally {
        $udp.Close()
        $tcp.Close()
    }
}
$started = $false
$failed = $false
$downloadClient = $null
$downloadClock = $null
$task = $null
$uploadClock = $null
$uploadTask = $null
$echoed = $null
$uploadWireguardChain = $null
$observedChain = $false
$downloaded = $null
$stage = 'mihomo-api'
try {
    ('request_timeout_ms=' + [ReleaseTestWebClient]::RequestTimeoutMilliseconds) | Out-File -LiteralPath $summary -Append -Encoding utf8
    ('transfer_timeout_ms=' + [ReleaseTestWebClient]::TransferTimeoutMilliseconds) | Out-File -LiteralPath $summary -Append -Encoding utf8
    $version = Read-Api '/version'
    ('mihomo=' + $version.version) | Out-File -LiteralPath $summary -Append -Encoding utf8
    $proxies = Read-Api '/proxies'
    $node = $proxies.proxies.PSObject.Properties[$ProxyName]
    if ($null -eq $node -or $node.Value.type -ne 'WireGuard') { throw '指定节点不是 WireGuard' }
    $ports = Read-Api '/configs'
    # 指定节点的健康检查绕过普通路由；下载与 UDP 必须由规则送入同一节点。
    $stage = 'mihomo-rule-mode'
    if ($ports.mode -ne 'rule') { throw '测试需要 mihomo 规则模式及目标 IP 的专用 WireGuard 规则' }
    Record 'mihomo-rule-mode'
    $mixedPort = [int]$ports.'mixed-port'
    $httpPort = [int]$ports.port
    $socksPort = [int]$ports.'socks-port'
    if ($mixedPort -gt 0) { $socksPort = $mixedPort; $httpPort = $mixedPort }
    if ($ProxyUrl -eq '') {
        if ($httpPort -eq 0) { throw '未找到 HTTP 或 mixed 入口，请用 -ProxyUrl 指定' }
        $ProxyUrl = 'http://127.0.0.1:' + $httpPort
    }
    if ($socksPort -eq 0) { throw 'UDP 测试需要 SOCKS 或 mixed 入口' }
    $ErrorActionPreference = 'Continue'
    $state = & $helper state -config $ConfigPath 2>$null
    $ErrorActionPreference = 'Stop'
    if ($LASTEXITCODE -eq 0 -and $state -ne 'idle') { throw '测试实例已有活动会话，请先停止再运行' }
    $stage = 'initialize'
    $started = $true
    Invoke-Cli 'restart'
    $before = Read-Helper 'info'
    if ($before.mtu -ne 1400 -or $before.peer_public_key -eq '') { throw '测试配置要求 MTU 1400 且填写对端公钥' }
    $stage = 'start'
    & $binary start -config $ConfigPath
    if ($LASTEXITCODE -ne 0) { throw '登录未成功' }
    Record 'start'
    $status = & $binary status -check -config $ConfigPath 2>&1
    if ($LASTEXITCODE -ne 0) { throw '隧道不在正常状态' }
    Record 'status'
    $stage = 'resources'
    $resources = Read-Helper 'resources'
    $resources | ConvertTo-Json | Out-File -LiteralPath (Join-Path $results 'resources-summary.json') -Encoding utf8
    $ErrorActionPreference = 'Continue'
    $lines = @(& $binary resources -config $ConfigPath 2>&1)
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($code -ne 0 -or $resources.apps -eq 0 -or $lines.Count -ne $resources.rows + 4) { throw 'IPv4 资源列表失败、为空或 DNS 打印不完整' }
    Record 'resources-complete'
    Invoke-Cli 'start'
    $again = Read-Helper 'resources'
    if ($resources.sha256 -ne $again.sha256) { throw '重复 start 改变了资源快照' }
    Record 'resources-repeat'
    $stage = 'wireguard-health'
    $delayPath = '/proxies/' + [Uri]::EscapeDataString($ProxyName) + '/delay?url=' + [Uri]::EscapeDataString($baseUrl + '/health') + '&timeout=' + [ReleaseTestWebClient]::RequestTimeoutMilliseconds + '&expected=200'
    $delay = Read-Api $delayPath
    if ($null -eq $delay.PSObject.Properties['delay']) { throw '指定 WireGuard 节点健康检查失败' }
    Record 'wireguard-health'
    $stage = 'download-request'
    $downloadClient = New-Object ReleaseTestWebClient ([ReleaseTestWebClient]::TransferTimeoutMilliseconds)
    $downloadClient.Proxy = New-Object Net.WebProxy $ProxyUrl
    $downloadClient.Headers['X-Njuvpn-Test-Id'] = $runId
    $downloadClock = [Diagnostics.Stopwatch]::StartNew()
    $task = $downloadClient.DownloadTransferAsync([Uri]($baseUrl + '/slow-blob'))
    $stage = 'download-progress'
    while (-not $task.IsCompleted) {
        if (-not $observedChain -and (Has-TestChain (Read-Api '/connections') 'tcp')) { $observedChain = $true }
        Start-Sleep -Milliseconds 100
    }
    $stage = 'download-result'
    $downloaded = $task.GetAwaiter().GetResult()
    $downloadClock.Stop()
    $stage = 'download-content'
    $expected = New-Payload (8 * 1024 * 1024) 256
    if ($downloaded.Length -ne $expected.Length -or (Digest $downloaded) -ne (Digest $expected)) { throw '8 MiB 下载内容不一致' }
    $stage = 'download-wireguard-chain'
    if (-not $observedChain) { throw '没有观察到下载经过指定 WireGuard 节点' }
    Record 'download-8MiB-wireguard-chain'
    ('download_elapsed_ms=' + $downloadClock.ElapsedMilliseconds) | Out-File -LiteralPath $summary -Append -Encoding utf8
    $stage = 'upload-request'
    $uploadClock = [Diagnostics.Stopwatch]::StartNew()
    if ($UploadClient -eq 'Go') {
        $existingConnections = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($connection in (Read-Api '/connections').connections) { [void]$existingConnections.Add($connection.id) }
        $uploadObservation = @{ seen = $false }
        $observeUpload = {
            if (-not $uploadObservation.seen) {
                $uploadObservation.seen = Has-TestChain (Read-Api '/connections') 'tcp' $existingConnections
            }
        }
        $stage = 'upload-go-result'
        try {
            Invoke-GoUpload (Join-Path $PSScriptRoot 'test-peer.exe') $ProxyUrl $runId (Join-Path $results 'upload-go-summary.json') (Join-Path $private 'upload-go.log') $observeUpload
        } finally { $uploadWireguardChain = $uploadObservation.seen }
        $stage = 'upload-go-wireguard-chain'
        if (-not $uploadWireguardChain) { throw '未观察到 Go 上传经过指定 WireGuard 节点' }
        Record 'upload-go-wireguard-chain'
    } else {
        $upload = New-Payload (1024 * 1024) 256
        $uploadTask = $downloadClient.UploadTransferAsync([Uri]($baseUrl + '/echo'), $upload)
        $stage = 'upload-result'
        $echoed = $uploadTask.GetAwaiter().GetResult()
        $stage = 'upload-content'
        if ($echoed.Length -ne $upload.Length -or (Digest $echoed) -ne (Digest $upload)) { throw '1 MiB 上传回传内容不一致' }
        Read-UploadProgress $downloadClient | ConvertTo-Json -Depth 2 | Out-File -LiteralPath (Join-Path $results 'upload-progress.json') -Encoding utf8
    }
    $uploadClock.Stop()
    Record 'upload-1MiB'
    ('upload_elapsed_ms=' + $uploadClock.ElapsedMilliseconds) | Out-File -LiteralPath $summary -Append -Encoding utf8
    $stage = 'udp'
    Test-Udp $socksPort
    $stage = 'heartbeat'
    Start-Sleep -Seconds 50
    $status = & $binary status -check -config $ConfigPath 2>&1
    if ($LASTEXITCODE -ne 0) { throw '心跳后隧道状态异常' }
    Record 'heartbeat-survival'
    $stage = 'stop'
    Invoke-Cli 'stop'
    $ErrorActionPreference = 'Continue'
    $status = & $binary status -check -config $ConfigPath 2>&1
    $stoppedCode = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($stoppedCode -eq 0) { throw 'stop 后 status -check 仍然成功' }
    Record 'stopped-status'
    $stillReachable = $false
    try {
        $stoppedDelay = Read-Api $delayPath
        $stillReachable = $null -ne $stoppedDelay.PSObject.Properties['delay']
    } catch [Net.WebException] {
        # 指定 WireGuard 节点应在 stop 后失败；随后确认 API 自身仍存活。
    }
    [void](Read-Api '/version')
    if ($stillReachable) { throw 'stop 后指定 WireGuard 节点仍可访问测试资源' }
    Record 'stopped-wireguard-unreachable'
    $after = Read-Helper 'info'
    if ($before.identity_sha256 -ne $after.identity_sha256) { throw '测试改变了设备标识、承载密钥或 TLS 配置' }
    Record 'identity-stable'
} catch {
    $failed = $true
    if ($null -ne $downloadClock) { $downloadClock.Stop() }
    if ($null -ne $uploadClock) { $uploadClock.Stop() }
    $details = Read-SafeError $_.Exception
    $details['stage'] = $stage
    $details['wireguard_chain_seen'] = $observedChain
    $details['download_task_status'] = if ($null -eq $task) { $null } else { $task.Status.ToString() }
    $details['download_elapsed_ms'] = if ($null -eq $downloadClock) { $null } else { $downloadClock.ElapsedMilliseconds }
    $details['download_bytes'] = if ($null -eq $downloaded) { $null } else { $downloaded.Length }
    $details['upload_task_status'] = if ($null -eq $uploadTask) { $null } else { $uploadTask.Status.ToString() }
    $details['upload_elapsed_ms'] = if ($null -eq $uploadClock) { $null } else { $uploadClock.ElapsedMilliseconds }
    $details['upload_bytes'] = if ($null -eq $echoed) { $null } else { $echoed.Length }
    $details['upload_client'] = $UploadClient
    $details['upload_wireguard_chain_seen'] = $uploadWireguardChain
    $details['upload_progress'] = Read-UploadProgress $downloadClient
    $details['vpn_status_after_failure'] = $null
    if ($started) {
        # 清理前检查承载是否仍在线；实际输出仅留在本机私有目录。
        $savedPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            & $binary status -check -config $ConfigPath 2>&1 | Out-File -LiteralPath (Join-Path $private 'failure-status.log') -Encoding utf8
            $details['vpn_status_after_failure'] = ($LASTEXITCODE -eq 0)
        } catch {
            $details['vpn_status_after_failure'] = $null
        } finally { $ErrorActionPreference = $savedPreference }
    }
    $details | ConvertTo-Json -Depth 3 | Out-File -LiteralPath (Join-Path $results 'failure-details.json') -Encoding utf8
    $line = 'FAIL ' + $stage + '; error_type=' + $_.Exception.GetType().Name
    Write-Host $line
    $line | Out-File -LiteralPath $summary -Append -Encoding utf8
} finally {
    if ($started) {
        $ErrorActionPreference = 'Continue'
        & $binary stop -config $ConfigPath 2>&1 | Out-File -LiteralPath (Join-Path $private 'cleanup.log') -Encoding utf8
        & $helper shutdown -config $ConfigPath 2>&1 | Out-File -LiteralPath (Join-Path $private 'cleanup.log') -Append -Encoding utf8
        $ErrorActionPreference = 'Stop'
    }
    if ($null -ne $downloadClient) {
        # API 或其他步骤失败时，也取消并等待当前传输，释放它的期限计时器。
        $downloadClient.CancelAsync()
        foreach ($pending in @($task, $uploadTask)) {
            if ($null -ne $pending) { try { [void]$pending.GetAwaiter().GetResult() } catch { } }
        }
        $downloadClient.Dispose()
    }
    $api.Dispose()
    $secret.Dispose()
}
Get-Content -LiteralPath $summary
$archive = $results + '.zip'
Compress-Archive -LiteralPath $results -DestinationPath $archive
Write-Host ('请回传：' + $archive)
Write-Host ('原始输出（不要回传）：' + $private)
if ($failed) { exit 1 }
