param([string]$PeerToolPath = '')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$sourcePath = Join-Path $PSScriptRoot 'live-windows.ps1'
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput([IO.File]::ReadAllText($sourcePath, [Text.Encoding]::UTF8), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw '脚本语法检查失败' }
$addType = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Add-Type' }, $true))
if ($addType.Count -ne 1) { throw '测试要求唯一的 Add-Type 定义' }
Invoke-Expression $addType[0].Extent.Text
foreach ($name in @('Read-SafeError', 'Read-UploadProgress', 'Invoke-GoUpload', 'Has-TestChain')) {
    $function = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true))
    if ($function.Count -ne 1) { throw ('缺少诊断函数：' + $name) }
    Invoke-Expression $function[0].Extent.Text
}
if ($null -ne (Read-UploadProgress $null)) { throw '不存在的进度被表示成已读取零字节' }
if ([ReleaseTestWebClient]::RequestTimeoutMilliseconds -ne 30000) { throw '普通请求期限改变' }
$target = '192.0.2.1'
$ProxyName = 'fixed-wireguard'
$knownIds = New-Object 'Collections.Generic.HashSet[string]'
[void]$knownIds.Add('previous-download')
$oldConnection = [pscustomobject]@{ id = 'previous-download'; metadata = [pscustomobject]@{ destinationIP = '192.0.2.1'; network = 'tcp' }; chains = @('fixed-wireguard') }
$oldOnly = [pscustomobject]@{ connections = @($oldConnection) }
if (-not (Has-TestChain $oldOnly 'tcp') -or (Has-TestChain $oldOnly 'tcp' $knownIds)) { throw '旧下载连接被误认为新上传的链路' }
$newConnection = [pscustomobject]@{ id = 'new-upload'; metadata = [pscustomobject]@{ destinationIP = '192.0.2.1'; network = 'tcp' }; chains = @('fixed-wireguard') }
if (-not (Has-TestChain ([pscustomobject]@{ connections = @($oldConnection, $newConnection) }) 'tcp' $knownIds)) { throw '没有识别新上传的指定链路' }
$newConnection.chains = @('DIRECT')
if (Has-TestChain ([pscustomobject]@{ connections = @($oldConnection, $newConnection) }) 'tcp' $knownIds) { throw '直连上传被误认为指定链路' }
Write-Output 'PASS new upload chain excludes old connections and DIRECT'
Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
public sealed class FixedErrorServer : IDisposable {
    private readonly TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
    private readonly Task worker;
    public readonly int Port;
    public FixedErrorServer(int status, bool truncated) {
        listener.Start();
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        worker = Task.Run(() => {
            using (TcpClient client = listener.AcceptTcpClient()) {
                client.ReceiveTimeout = 5000;
                client.SendTimeout = 5000;
                using (NetworkStream stream = client.GetStream()) {
                    byte[] request = new byte[4096];
                    stream.Read(request, 0, request.Length);
                    byte[] body = Encoding.ASCII.GetBytes("do-not-print-password-token-response");
                    byte[] header = Encoding.ASCII.GetBytes("HTTP/1.1 " + status + " Fixed\r\nContent-Length: " + (truncated ? body.Length + 1024 : body.Length) + "\r\nConnection: close\r\n\r\n");
                    stream.Write(header, 0, header.Length);
                    stream.Write(body, 0, body.Length);
                }
            }
        });
    }
    public void Dispose() {
        listener.Stop();
        worker.GetAwaiter().GetResult();
    }
}
'@
$server = [FixedErrorServer]::new(502, $false)
$client = New-Object ReleaseTestWebClient
$client.Proxy = $null
$caught = $false
try {
    $task = $client.DownloadTransferAsync([Uri]("http://127.0.0.1:" + $server.Port + "/do-not-print-secret-path"))
    try {
        $data = $task.GetAwaiter().GetResult()
    } catch {
        $caught = $true
        $safe = Read-SafeError $_.Exception
        if ($_.Exception.GetType().Name -ne 'MethodInvocationException' -or $safe.web_status -ne 'ProtocolError' -or $safe.http_status -ne 502) { throw 'HTTP 错误分类不符' }
        $json = $safe | ConvertTo-Json -Depth 3 -Compress
        if ($json.Contains('do-not-print') -or $json.Contains('127.0.0.1') -or $json.Length -gt 4096) { throw 'HTTP 诊断超出上限或未脱敏' }
        $cause = $_.Exception.GetBaseException()
        if ($cause -is [Net.WebException] -and $null -ne $cause.Response) { $cause.Response.Close() }
    }
    if (-not $caught) { throw '错误接受固定的 502 响应' }
} finally {
    $client.Dispose()
    $server.Dispose()
}
$server = [FixedErrorServer]::new(200, $true)
$client = New-Object ReleaseTestWebClient
$client.Proxy = $null
$caught = $false
try {
    $task = $client.DownloadTransferAsync([Uri]("http://127.0.0.1:" + $server.Port + "/fixed-truncated"))
    try { $body = $task.GetAwaiter().GetResult() } catch {
        $caught = $true
        $safe = Read-SafeError $_.Exception
        if ($safe.web_status -ne 'UnknownError' -or $safe.error_types -notcontains 'System.IO.IOException') { throw '截断响应的错误类别不符' }
        $safe | ConvertTo-Json -Depth 3 -Compress
    }
    if (-not $caught) { throw '错误接受固定的截断响应' }
} finally {
    $client.Dispose()
    $server.Dispose()
}
$socket = [Net.Sockets.SocketException]::new(10054)
$wrapper = [Exception]::new('do-not-print-password-private-address', $socket)
$safe = Read-SafeError $wrapper
if ($safe.socket_error -ne 'ConnectionReset' -or $safe.native_error -ne 10054) { throw 'Socket 错误分类不符' }
if (($safe | ConvertTo-Json -Depth 3 -Compress).Contains('do-not-print')) { throw 'Socket 诊断包含错误正文' }
$nested = $socket
for ($i = 0; $i -lt 12; $i++) { $nested = [Exception]::new('do-not-print-token', $nested) }
$safe = Read-SafeError $nested
if ($safe.error_types.Count -ne 8 -or -not $safe.chain_truncated) { throw '异常链超出层数上限' }
@{ pass = $true; native_http_502 = $true; native_truncated_response = $true; socket_reset = $true; redacted = $true; max_exception_types = 8; request_timeout_ms = 30000 } | ConvertTo-Json -Compress

# 持续发送数据也必须受总体期限约束；下载与上传都用同一取消工序。
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
public sealed class PacedEchoServer : IDisposable {
    private readonly TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
    private readonly Task worker;
    public readonly int Port;
    public bool Completed { get; private set; }
    public PacedEchoServer(int interval) {
        listener.Start();
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        worker = Task.Run(() => {
            using (TcpClient client = listener.AcceptTcpClient()) {
                client.ReceiveTimeout = 5000;
                client.SendTimeout = 5000;
                try {
                    using (NetworkStream stream = client.GetStream()) {
                        StringBuilder request = new StringBuilder();
                        while (!request.ToString().EndsWith("\r\n\r\n")) {
                            if (request.Length >= 4096) { throw new InvalidDataException(); }
                            int next = stream.ReadByte();
                            if (next < 0) { return; }
                            request.Append((char)next);
                        }
                        byte[] body = Encoding.ASCII.GetBytes("abcdef");
                        if (request.ToString().StartsWith("POST ")) {
                            if (request.ToString().IndexOf("Expect: 100-continue", StringComparison.OrdinalIgnoreCase) >= 0) {
                                byte[] ready = Encoding.ASCII.GetBytes("HTTP/1.1 100 Continue\r\n\r\n");
                                stream.Write(ready, 0, ready.Length);
                            }
                            for (int i = 0; i < body.Length; i++) {
                                int next = stream.ReadByte();
                                if (next < 0) { return; }
                                if (next != body[i]) { throw new InvalidDataException(); }
                            }
                        }
                        byte[] header = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\n");
                        stream.Write(header, 0, header.Length);
                        for (int i = 0; i < body.Length; i++) {
                            Thread.Sleep(interval);
                            stream.WriteByte(body[i]);
                        }
                        Completed = true;
                    }
                } catch (IOException) { /* 总体期限取消客户端时，目标端也退出。 */ }
            }
        });
    }
    public void Dispose() {
        listener.Stop();
        worker.GetAwaiter().GetResult();
    }
}
'@
foreach ($method in @('download', 'upload')) {
    foreach ($budget in @(150, 2000)) {
        $server = [PacedEchoServer]::new(100)
        $client = [ReleaseTestWebClient]::new($budget)
        $client.Proxy = $null
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $caught = $false
        try {
            $uri = [Uri]('http://127.0.0.1:' + $server.Port + '/fixed-payload')
            if ($method -eq 'download') { $task = $client.DownloadTransferAsync($uri) }
            else { $task = $client.UploadTransferAsync($uri, [Text.Encoding]::ASCII.GetBytes('abcdef')) }
            try { $body = $task.GetAwaiter().GetResult() } catch {
                $caught = $true
                $safe = Read-SafeError $_.Exception
                if ($budget -ne 150 -or $safe.error_types -notcontains 'System.TimeoutException') { throw '慢速传输出现非预期错误' }
                if ($clock.ElapsedMilliseconds -gt 2000) { throw '传输取消超出等待上限' }
            }
            if ($budget -eq 150 -and -not $caught) { throw '持续传输绕过了总期限' }
            if ($budget -eq 2000 -and ($caught -or [Text.Encoding]::ASCII.GetString($body) -ne 'abcdef')) { throw '较长传输期限内未收到完整固定载荷' }
            if ($method -eq 'upload' -and $budget -eq 2000) {
                # 运行库进度通知异步投递；只等这一份固定载荷的最终计数。
                $progressClock = [Diagnostics.Stopwatch]::StartNew()
                do {
                    $progress = $client.GetUploadProgress()
                    if ($null -ne $progress -and $progress.BytesReceived -eq 6) { break }
                    Start-Sleep -Milliseconds 10
                } while ($progressClock.ElapsedMilliseconds -lt 1000)
                if ($null -eq $progress -or $progress.BytesSent -ne 6 -or $progress.TotalBytesToSend -ne 6 -or $progress.BytesReceived -ne 6 -or $progress.TotalBytesToReceive -ne 6) { throw '上传进度不符合独立的固定载荷' }
                $safeProgress = Read-UploadProgress $client
                if ($safeProgress.Count -ne 4 -or $safeProgress.bytes_sent -ne 6 -or $safeProgress.bytes_received -ne 6) { throw '上传计数包含额外数据或值不符' }
                Write-Output 'PASS native upload progress fixed bytes'
            }
        } finally {
            $client.Dispose()
            $server.Dispose()
        }
        if ($budget -eq 2000 -and -not $server.Completed) { throw '服务端工作者未完成' }
        Write-Output ('PASS ' + $method + ' timeout_ms=' + $budget)
    }
}
Write-Output 'PASS native transfer deadlines and fixed payloads'

if ($PeerToolPath -ne '') {
    $priorTarget = [Environment]::GetEnvironmentVariable('NJUVPN_TEST_TARGET_IP')
    $env:NJUVPN_TEST_TARGET_IP = '192.0.2.1'
    $PeerToolPath = (Resolve-Path -LiteralPath $PeerToolPath).ProviderPath
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
public sealed class FixedUploadProxy : IDisposable {
    private readonly TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
    private readonly Task worker;
    public readonly int Port;
    public FixedUploadProxy(int status, int replyDelay = 0) {
        listener.Start();
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        worker = Task.Run(() => {
            using (TcpClient client = listener.AcceptTcpClient()) {
                client.ReceiveTimeout = 5000;
                client.SendTimeout = 5000;
                try { using (NetworkStream stream = client.GetStream()) {
                    StringBuilder header = new StringBuilder();
                    while (!header.ToString().EndsWith("\r\n\r\n")) {
                        if (header.Length >= 4096) { throw new InvalidDataException(); }
                        int next = stream.ReadByte();
                        if (next < 0) { throw new EndOfStreamException(); }
                        header.Append((char)next);
                    }
                    if (!header.ToString().StartsWith("POST http://192.0.2.1:18080/echo HTTP/1.1\r\n") ||
                        !header.ToString().Contains("Content-Length: 1048576\r\n") ||
                        !header.ToString().Contains("Expect: 100-continue\r\n")) { throw new InvalidDataException(); }
                    byte[] ready = Encoding.ASCII.GetBytes("HTTP/1.1 100 Continue\r\n\r\n");
                    stream.Write(ready, 0, ready.Length);
                    byte[] body = new byte[1048576];
                    int count = 0;
                    while (count < body.Length) {
                        int n = stream.Read(body, count, body.Length - count);
                        if (n == 0) { throw new EndOfStreamException(); }
                        count += n;
                    }
                    for (int i = 0; i < body.Length; i++) {
                        if (body[i] != (byte)(i % 256)) { throw new InvalidDataException(); }
                    }
                    System.Threading.Thread.Sleep(replyDelay);
                    byte[] reply = Encoding.ASCII.GetBytes("HTTP/1.1 " + status + " Fixed\r\nContent-Length: " + (status == 200 ? 1048576 : 0) + "\r\nConnection: close\r\n\r\n");
                    stream.Write(reply, 0, reply.Length);
                    if (status == 200) { stream.Write(body, 0, body.Length); }
                } } catch (IOException) { if (replyDelay == 0) { throw; } }
            }
        });
    }
    public void Dispose() { listener.Stop(); worker.GetAwaiter().GetResult(); }
}
'@
    $folder = Join-Path $env:TEMP ('njuvpn-http-client-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $folder | Out-Null
    try {
        foreach ($status in @(200, 502)) {
            $server = [FixedUploadProxy]::new($status)
            $resultPath = Join-Path $folder ('result 空格 ' + $status + '.json')
            $privatePath = Join-Path $folder ('private-' + $status + '.log')
            $runId = '0123456789abcdef0123456789abcdef'
            $caught = $false
            try {
                try { Invoke-GoUpload $PeerToolPath ('http://127.0.0.1:' + $server.Port) $runId $resultPath $privatePath }
                catch { $caught = $true }
                if ($caught -ne ($status -eq 502)) { throw 'Go 上传适配器错误接受或拒绝固定状态' }
                $result = Get-Content -LiteralPath $resultPath -Raw -Encoding utf8 | ConvertFrom-Json
                if ($result.check.http_status -ne $status -or $result.run_id -ne $runId) { throw 'Go 上传结果状态或标识不符' }
                if ($status -eq 502 -and ($result.passed -or $result.check.error_category -ne 'http-status-or-length')) { throw 'Go 上传 502 未保留固定错误判据' }
            } finally { $server.Dispose() }
            Write-Output ('PASS native Go upload adapter status=' + $status)
        }
        $server = [FixedUploadProxy]::new(200, 500)
        $owner = @{ id = $null }
        $observationFailure = { $owner.id = $process.Id; throw '固定的 API 观察失败' }
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $caught = $false
        try {
            try { Invoke-GoUpload $PeerToolPath ('http://127.0.0.1:' + $server.Port) '0123456789abcdef0123456789abcdef' (Join-Path $folder 'cancel.json') (Join-Path $folder 'cancel.log') $observationFailure }
            catch { $caught = $true }
            if (-not $caught -or $null -eq $owner.id -or $clock.ElapsedMilliseconds -gt 2000) { throw 'Go 上传观察失败没有及时回收子进程' }
            $stillRunning = $false
            try {
                $remaining = [Diagnostics.Process]::GetProcessById($owner.id)
                $remaining.Dispose()
                $stillRunning = $true
            } catch [ArgumentException] { }
            if ($stillRunning) { throw 'Go 上传子进程残留' }
            Write-Output 'PASS native Go upload child cancelled and joined'
        } finally { $server.Dispose() }
    } finally {
        [Environment]::SetEnvironmentVariable('NJUVPN_TEST_TARGET_IP', $priorTarget)
        Remove-Item -LiteralPath $folder -Recurse -Force
    }
}
