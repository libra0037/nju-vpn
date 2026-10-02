param([Parameter(Mandatory = $true)][string]$ConfigPath, [switch]$PacketChecks)
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
$resultPrefix = if ($PacketChecks) { 'results-packets-' } else { 'results-direct-' }
$results = Join-Path $PSScriptRoot ($resultPrefix + $runId)
$private = Join-Path (Split-Path -Parent $ConfigPath) ('private-direct-' + $runId)
$testConfig = Join-Path $private 'config.yaml'
New-Item -ItemType Directory -Path $results | Out-Null
$summary = Join-Path $results 'summary.txt'
& $binary version | Out-File -LiteralPath $summary -Encoding utf8
Get-Content -LiteralPath (Join-Path $PSScriptRoot 'BUILD.txt') | Out-File -LiteralPath $summary -Append -Encoding utf8
foreach ($entry in @(@('binary_sha256', $binary), @('peer_binary_sha256', $peer), @('direct_script_sha256', $PSCommandPath))) {
    ($entry[0] + '=' + (Get-FileHash -LiteralPath $entry[1] -Algorithm SHA256).Hash.ToLowerInvariant()) |
        Out-File -LiteralPath $summary -Append -Encoding utf8
}
('run_id=' + $runId) | Out-File -LiteralPath $summary -Append -Encoding utf8
('packet_checks=' + [bool]$PacketChecks) | Out-File -LiteralPath $summary -Append -Encoding utf8
$originalHash = (Get-FileHash -LiteralPath $ConfigPath -Algorithm SHA256).Hash
$owned = $false
$failed = $false
$stage = 'existing-state'
function Record([string]$Name) {
    $line = 'PASS ' + $Name
    Write-Host $line
    $line | Out-File -LiteralPath $summary -Append -Encoding utf8
}
function Info {
    $ErrorActionPreference = 'Continue'
    $data = & $helper info -config $testConfig
    if ($LASTEXITCODE -ne 0) { throw '读取独立测试配置失败' }
    return ($data | ConvertFrom-Json)
}
function Logged-Cli([string]$Command, [string[]]$Options = @()) {
    # PowerShell 5.1 会把普通 stderr 也转成 ErrorRecord；判据使用实际退出码。
    $ErrorActionPreference = 'Continue'
    $data = & $binary $Command @Options -config $testConfig 2>&1
    $code = $LASTEXITCODE
    $data | ForEach-Object { "$_" } | Out-File -LiteralPath (Join-Path $private ($stage + '.log')) -Encoding utf8
    return $code
}
try {
    $ErrorActionPreference = 'Continue'
    $prior = & $helper state -config $ConfigPath 2>$null
    $priorCode = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($priorCode -eq 0 -and $prior -ne 'idle') { throw '原测试实例仍有活动会话' }
    $stage = 'prepare'
    & $peer prepare -config $ConfigPath -out $private
    if ($LASTEXITCODE -ne 0) { throw '独立测试配置生成失败' }
    Record 'separate-config-peer-port'
    $owned = $true
    $stage = 'restart'
    if ((Logged-Cli 'restart') -ne 0) { throw '独立服务进程启动失败' }
    Record 'restart'
    $before = Info
    $stage = 'start'
    $ErrorActionPreference = 'Continue'
    & $binary start -config $testConfig
    $startCode = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($startCode -ne 0) { throw '登录失败' }
    Record 'start'
    $stage = 'status'
    if ((Logged-Cli 'status' @('-check')) -ne 0) { throw '隧道状态异常' }
    Record 'status'
    $stage = 'resources'
    $ErrorActionPreference = 'Continue'
    $data = & $helper resources -config $testConfig
    $jsonCode = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($jsonCode -ne 0) { throw '资源查询失败' }
    $resources = $data | ConvertFrom-Json
    $resources | ConvertTo-Json | Out-File -LiteralPath (Join-Path $results 'resources-summary.json') -Encoding utf8
    $ErrorActionPreference = 'Continue'
    $lines = @(& $binary resources -config $testConfig 2>&1)
    $resourceCode = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($resourceCode -ne 0 -or $resources.apps -eq 0 -or $lines.Count -ne $resources.rows + 1) { throw '资源打印不完整' }
    Record 'resources-complete'
    $stage = 'direct-traffic'
    $ErrorActionPreference = 'Continue'
    $peerCommand = if ($PacketChecks) { 'packet-check' } else { 'run' }
    & $peer $peerCommand -config $testConfig -key (Join-Path $private 'peer.key') -result (Join-Path $results 'traffic-summary.json') -run-id $runId 2>&1 |
        Out-File -LiteralPath (Join-Path $private 'peer.log') -Encoding utf8
    $peerCode = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    $traffic = Get-Content -LiteralPath (Join-Path $results 'traffic-summary.json') -Raw | ConvertFrom-Json
    foreach ($check in $traffic.checks) {
        $stage = 'direct-' + $check.name
        if (-not $check.passed) { throw '固定载荷流量校验失败' }
        Record $stage
    }
    $stage = 'direct-handshake'
    if ($peerCode -ne 0 -or -not $traffic.passed -or -not $traffic.wireguard_handshake_seen) { throw '直接对端未完整通过' }
    Record 'direct-wireguard-handshake'
    $stage = 'heartbeat'
    Start-Sleep -Seconds 50
    if ((Logged-Cli 'status' @('-check')) -ne 0) { throw '空闲后隧道状态异常' }
    Record 'heartbeat-survival'
    $stage = 'stop'
    if ((Logged-Cli 'stop') -ne 0) { throw '断开失败' }
    Record 'stop'
    $stage = 'stopped-status'
    $stoppedCode = Logged-Cli 'status' @('-check')
    if ($stoppedCode -eq 0) { throw '断开后仍在正常状态' }
    Record 'stopped-status'
    $stage = 'identity'
    $after = Info
    if ($before.identity_sha256 -ne $after.identity_sha256) { throw '独立配置的身份被改动' }
    Record 'identity-stable'
} catch {
    $failed = $true
    $line = 'FAIL ' + $stage + '; error_type=' + $_.Exception.GetType().Name
    Write-Host $line
    $line | Out-File -LiteralPath $summary -Append -Encoding utf8
} finally {
    if ($owned) {
        $ErrorActionPreference = 'Continue'
        & $binary stop -config $testConfig 2>&1 | Out-File -LiteralPath (Join-Path $private 'cleanup.log') -Encoding utf8
        & $helper shutdown -config $testConfig 2>&1 | Out-File -LiteralPath (Join-Path $private 'cleanup.log') -Append -Encoding utf8
        if ($LASTEXITCODE -ne 0) {
            $failed = $true
            'FAIL shutdown' | Out-File -LiteralPath $summary -Append -Encoding utf8
        }
        $ErrorActionPreference = 'Stop'
    }
    if ((Get-FileHash -LiteralPath $ConfigPath -Algorithm SHA256).Hash -ne $originalHash) {
        $failed = $true
        'FAIL original-config-changed' | Out-File -LiteralPath $summary -Append -Encoding utf8
    } else {
        Record 'original-config-unchanged'
    }
}
Get-Content -LiteralPath $summary
$archive = $results + '.zip'
Compress-Archive -LiteralPath $results -DestinationPath $archive
Write-Host ('请回传：' + $archive)
Write-Host ('私有配置、密钥和原始输出（不要回传）：' + $private)
if ($failed) { exit 1 }
