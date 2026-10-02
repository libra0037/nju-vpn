param([Parameter(Mandatory = $true)][string]$PeerToolPath)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [Text.Encoding]::UTF8
Add-Type -AssemblyName System.IO.Compression.FileSystem
$directory = Join-Path ([IO.Path]::GetTempPath()) ('njuvpn-log-test-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $directory | Out-Null
try {
    $configPath = Join-Path $directory '测试 配置.yaml'
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot '..\..\config.example.yaml') -Destination $configPath
    $configDigest = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash
    # 固定 Windows 文件名契约的独立判据，不从被测工具的输出取得实例标识。
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = $algorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($configPath.ToLowerInvariant()))
        $tag = [BitConverter]::ToString($hash, 0, 4).Replace('-', '').ToLowerInvariant()
    } finally { $algorithm.Dispose() }
    $logPath = Join-Path $directory ('njuvpn-' + $tag + '-config.log')
    $body = @'
2026/10/02 12:34:00 njuvpn 服务进程启动 pid=42 账号="private-user" 配置="secret-path"
2026/10/02 12:34:01 隧道连接已建立
2026/10/02 12:34:02 wireguard: 丢弃 下行队列已满（累计 19 个）
2026/10/02 12:34:03 隧道断开: secret-token at 192.0.2.1:443
'@
    [IO.File]::WriteAllText($logPath, $body, [Text.UTF8Encoding]::new($false))
    $logDigest = (Get-FileHash -LiteralPath $logPath -Algorithm SHA256).Hash
    [IO.File]::WriteAllText((Join-Path $directory 'njuvpn-other-config.log'), 'secret-token', [Text.Encoding]::UTF8)
    $id = '0123456789abcdef0123456789abcdef'
    New-Item -ItemType Directory -Path (Join-Path $directory ('results-live-' + $id)) | Out-Null
    & (Join-Path $PSScriptRoot 'collect-logs-windows.ps1') -ConfigPath $configPath -ToolPath $PeerToolPath -OutputDirectory $directory
    $archives = @(Get-ChildItem -LiteralPath $directory -Filter 'results-log-*.zip')
    if ($archives.Count -ne 1) { throw '未生成唯一日志摘要包' }
    $archive = [IO.Compression.ZipFile]::OpenRead($archives[0].FullName)
    try {
        $objects = @{}
        foreach ($entry in $archive.Entries) {
            if ($entry.Name -eq '') { continue }
            if ($entry.Name -notin @('daemon-summary.json', 'summary.json')) { throw '日志摘要包含有未授权文件' }
            $stream = [IO.StreamReader]::new($entry.Open(), [Text.Encoding]::UTF8)
            try { $text = $stream.ReadToEnd() } finally { $stream.Dispose() }
            if ($text.Contains('private-user') -or $text.Contains('secret-') -or $text.Contains('192.0.2.1') -or $text.Contains($directory)) { throw '摘要泄露原文、路径或地址' }
            $objects[$entry.Name] = $text | ConvertFrom-Json
        }
        $logs = $objects['daemon-summary.json']
        if (-not $logs.found -or $logs.files_scanned -ne 1 -or $logs.events.Count -ne 4 -or $logs.events_omitted -ne 0) { throw '日志选择或事件数量不符' }
        if ($logs.events[0].kind -ne 'service_started' -or $logs.events[2].reason -ne 'downlink_full' -or $logs.events[2].count -ne 19 -or $logs.events[3].kind -ne 'tunnel_closed') { throw '日志固定分类不符' }
        if (@($logs.events | Where-Object { $_.pid -ne 42 }).Count -ne 0) { throw '事件进程归属不符' }
        if ($objects['summary.json'].recent_runs.Count -ne 1 -or $objects['summary.json'].recent_runs[0].run_id -ne $id) { throw '结果目录标识关联不符' }
    } finally { $archive.Dispose() }
    if ((Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash -ne $configDigest -or (Get-FileHash -LiteralPath $logPath -Algorithm SHA256).Hash -ne $logDigest) { throw '日志收集修改了配置或原日志' }
    $oversized = Join-Path $directory 'oversized-results'
    New-Item -ItemType Directory -Path $oversized | Out-Null
    for ($i = 0; $i -lt 257; $i++) { New-Item -ItemType File -Path (Join-Path $oversized $i.ToString()) | Out-Null }
    $caught = $false
    try {
        & (Join-Path $PSScriptRoot 'collect-logs-windows.ps1') -ConfigPath $configPath -ToolPath $PeerToolPath -OutputDirectory $oversized
    } catch { $caught = $true }
    if (-not $caught) { throw '无关文件超过目录资源上限仍然被接受' }
    Write-Output 'PASS native result directory rejects more than 256 entries including unrelated files'
    Write-Output 'PASS native read-only log collector, fixed categories, archive allowlist and redaction'
} finally {
    Remove-Item -LiteralPath $directory -Recurse -Force
}
