param(
    [Parameter(Mandatory = $true)][string]$ConfigPath,
    [string]$ToolPath = '',
    [string]$OutputDirectory = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$ConfigPath = (Resolve-Path -LiteralPath $ConfigPath).ProviderPath
if ($ToolPath -eq '') { $ToolPath = Join-Path $PSScriptRoot 'test-peer.exe' }
if ($OutputDirectory -eq '') { $OutputDirectory = $PSScriptRoot }
$ToolPath = (Resolve-Path -LiteralPath $ToolPath).ProviderPath
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).ProviderPath
$runId = [Guid]::NewGuid().ToString('N')
$results = Join-Path $OutputDirectory ('results-log-' + $runId)
New-Item -ItemType Directory -Path $results | Out-Null
# 只调用日志摘要入口；不登录、启停 VPN，不访问 mihomo API，不读取结果正文。
& $ToolPath log-summary -config $ConfigPath -result (Join-Path $results 'daemon-summary.json')
if ($LASTEXITCODE -ne 0) { throw '日志摘要收集失败' }
$entries = @(Get-ChildItem -LiteralPath $OutputDirectory -Force | Select-Object -First 257)
if ($entries.Count -gt 256) { throw '结果目录超过 256 项上限' }
$recent = @($entries | Where-Object { $_.PSIsContainer -and $_.Name -like 'results-live-*' })
$runs = @()
foreach ($directory in @($recent | Sort-Object CreationTimeUtc -Descending | Select-Object -First 4)) {
    if ($directory.Name -notmatch '^results-live-([0-9a-f]{32})$') { continue }
    $runs += [ordered]@{
        run_id = $Matches[1]
        directory_created_utc = $directory.CreationTimeUtc.ToString('o')
        directory_modified_utc = $directory.LastWriteTimeUtc.ToString('o')
    }
}
[ordered]@{
    run_id = $runId
    tool_sha256 = (Get-FileHash -LiteralPath $ToolPath -Algorithm SHA256).Hash.ToLowerInvariant()
    script_sha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
    collected_utc = [DateTime]::UtcNow.ToString('o')
    recent_runs = $runs
} | ConvertTo-Json -Depth 4 | Out-File -LiteralPath (Join-Path $results 'summary.json') -Encoding utf8
Compress-Archive -LiteralPath $results -DestinationPath ($results + '.zip')
Write-Output ('请回传：' + $results + '.zip')
