param([Parameter(Mandatory = $true)][string]$ConfigPath)
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
$peer = Join-Path $PSScriptRoot 'test-peer.exe'
$runId = [Guid]::NewGuid().ToString('N')
$results = Join-Path $PSScriptRoot ('results-resilience-' + $runId)
$private = Join-Path (Split-Path -Parent $ConfigPath) ('private-resilience-' + $runId)
$instance = Join-Path $private 'instance'
$testConfig = Join-Path $instance 'config.yaml'
New-Item -ItemType Directory -Path $results, $private | Out-Null
$summary = Join-Path $results 'summary.txt'
& $binary version | Out-File -LiteralPath $summary -Encoding utf8
Get-Content -LiteralPath (Join-Path $PSScriptRoot 'BUILD.txt') | Out-File -LiteralPath $summary -Append -Encoding utf8
foreach ($entry in @(@('binary_sha256', $binary), @('peer_binary_sha256', $peer), @('resilience_script_sha256', $PSCommandPath))) {
    ($entry[0] + '=' + (Get-FileHash -LiteralPath $entry[1] -Algorithm SHA256).Hash.ToLowerInvariant()) |
        Out-File -LiteralPath $summary -Append -Encoding utf8
}
('run_id=' + $runId) | Out-File -LiteralPath $summary -Append -Encoding utf8
$failed = $false
try {
    Write-Host '开始受控断线测试：短暂断线、心跳判死、重连预算和重连期间 stop。'
    $ErrorActionPreference = 'Continue'
    & $peer resilience -config $ConfigPath -binary $binary -out $instance -result (Join-Path $results 'resilience-summary.json') -run-id $runId 2>&1 |
        Out-File -LiteralPath (Join-Path $private 'wrapper.log') -Encoding utf8
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    $report = Get-Content -LiteralPath (Join-Path $results 'resilience-summary.json') -Raw | ConvertFrom-Json
    foreach ($check in $report.checks) {
        if (-not $check.passed) { throw '故障或恢复判据未满足' }
        ('PASS ' + $check.name) | Out-File -LiteralPath $summary -Append -Encoding utf8
    }
    if ($code -ne 0 -or -not $report.passed -or -not $report.service_stopped -or -not $report.proxy_stopped -or
        -not $report.original_config_unchanged -or -not $report.private_config_unchanged) { throw '断线测试或收尾失败' }
    'PASS service-proxy-stopped-and-configs-unchanged' | Out-File -LiteralPath $summary -Append -Encoding utf8
} catch {
    $failed = $true
    ('FAIL resilience; error_type=' + $_.Exception.GetType().Name) | Out-File -LiteralPath $summary -Append -Encoding utf8
} finally {
    # 被中断时仍尝试释放本脚本创建的实例；原配置仅供读取。
    if (Test-Path -LiteralPath $testConfig) {
        $ErrorActionPreference = 'Continue'
        & $binary stop -config $testConfig 2>&1 | Out-File -LiteralPath (Join-Path $private 'cleanup.log') -Encoding utf8
        & $helper shutdown -config $testConfig 2>&1 | Out-File -LiteralPath (Join-Path $private 'cleanup.log') -Append -Encoding utf8
        $ErrorActionPreference = 'Stop'
    }
}
Get-Content -LiteralPath $summary
$archive = $results + '.zip'
Compress-Archive -LiteralPath $results -DestinationPath $archive
Write-Host ('请回传：' + $archive)
Write-Host ('私有配置、密钥和原始日志（不要回传）：' + $private)
if ($failed) { exit 1 }
