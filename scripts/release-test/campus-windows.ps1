param(
    [Parameter(Mandatory = $true)][string]$ConfigPath,
    [string]$BundlePath = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$OutputEncoding = [Text.Encoding]::UTF8
# Windows PowerShell 5.1 的参数默认值阶段尚无脚本目录，在正文中推导路径。
if ($BundlePath -eq '') { $BundlePath = Split-Path -Parent $PSScriptRoot }
# 相对输入先按用户工作目录解析，再进入补充包目录。
$ConfigPath = (Resolve-Path -LiteralPath $ConfigPath).ProviderPath
$BundlePath = (Resolve-Path -LiteralPath $BundlePath).ProviderPath
. (Join-Path $PSScriptRoot 'target.ps1')
[void](Get-TestTarget)
$binary = Join-Path $BundlePath 'njuvpn.exe'
$peer = Join-Path $PSScriptRoot 'test-peer-campus.exe'
$nativeTests = Join-Path $PSScriptRoot 'campus.test.exe'
if ((Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant() -ne '7508e6b469f0b1d86f877a3d4a983a2bad7f98a214f9831a1b60cc9f809a3627') {
    throw '要求原 v0.x-preflight-20261007.2 Windows x64 包'
}
foreach ($line in Get-Content -LiteralPath (Join-Path $PSScriptRoot 'SHA256SUMS')) {
    if ($line -notmatch '^([0-9a-f]{64})  ([A-Za-z0-9_.-]+)$') { throw '补充包摘要格式错误' }
    $expected, $name = $Matches[1], $Matches[2]
    if ((Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $name) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) {
        throw ('补充包文件校验失败: ' + $name)
    }
}
$runId = [Guid]::NewGuid().ToString('N')
$results = Join-Path $PSScriptRoot ('results-campus-' + $runId)
$private = Join-Path (Split-Path -Parent $ConfigPath) ('private-campus-' + $runId)
$testConfig = Join-Path $private 'config.yaml'
New-Item -ItemType Directory -Path $results | Out-Null
$summary = Join-Path $results 'summary.txt'
@(
    ('run_id=' + $runId),
    ('started_utc=' + [DateTime]::UtcNow.ToString('o')),
    ('os=' + [Environment]::OSVersion.VersionString),
    ('powershell=' + $PSVersionTable.PSVersion.ToString()),
    ('architecture=' + $env:PROCESSOR_ARCHITECTURE)
) | Out-File -LiteralPath $summary -Encoding utf8
Get-Content -LiteralPath (Join-Path $PSScriptRoot 'BUILD.txt') | Out-File -LiteralPath $summary -Append -Encoding utf8
$originalHash = (Get-FileHash -LiteralPath $ConfigPath -Algorithm SHA256).Hash
$privateHash = ''
$daemonProcess = $null
$owned = $false
$failed = $false
$stage = 'native-campus-tests'
function Record([string]$Name) {
    $line = 'PASS ' + $Name
    Write-Host $line
    $line | Out-File -LiteralPath $summary -Append -Encoding utf8
}
function Logged([string]$File, [string[]]$Options, [string]$Log) {
    $ErrorActionPreference = 'Continue'
    & $File @Options 2>&1 | ForEach-Object {
        Write-Host "$_"
        "$_" | Out-File -LiteralPath $Log -Append -Encoding utf8
    }
    return $LASTEXITCODE
}
try {
    if ((Logged $nativeTests @('-test.v', '-test.run=^TestCampus', '-test.timeout=40s') (Join-Path $results 'native-campus-tests.log')) -ne 0) {
        throw '校园测试工具的原生离线用例失败'
    }
    Record 'native-campus-tests'
    $stage = 'prepare-private-config'
    if ((Logged $peer @('campus-prepare', '-config', $ConfigPath, '-out', $private) (Join-Path $results 'prepare.log')) -ne 0) {
        throw '独立配置准备失败；请检查原实例已断开且已有设备身份'
    }
    Record 'private-config-and-independent-ports'
    $owned = $true
    $stage = 'restart-private-instance'
    if ((Logged $binary @('restart', '-config', $testConfig) (Join-Path $results 'restart.log')) -ne 0) {
        throw '独立服务启动失败'
    }
    $privateHash = (Get-FileHash -LiteralPath $testConfig -Algorithm SHA256).Hash
    Record 'restart-private-instance'
    if ((Logged $binary @('status', '-json', '-config', $testConfig) (Join-Path $results 'idle-status.log')) -ne 4) {
        throw '新实例应处于 idle，status 退出码应为 4'
    }
    $idleStatus = Get-Content -LiteralPath (Join-Path $results 'idle-status.log') -Raw | ConvertFrom-Json
    $daemonProcess = Get-Process -Id $idleStatus.identity.pid
    Record 'private-instance-idle'
    $stage = 'real-campus-login'
    Write-Host '现在登录真实校园账号；如需口令或短信验证码，请在此电脑的提示中填写。'
    # 保留交互终端，避免把口令/SMS 提示困在重定向文件中。
    $ErrorActionPreference = 'Continue'
    & $binary start -config $testConfig
    $startCode = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($startCode -ne 0) { throw '真实校园登录失败' }
    Record 'real-campus-login'
    $stage = 'real-campus-checks'
    if ((Logged $binary @('status', '-json', '-config', $testConfig) (Join-Path $results 'initial-status.log')) -ne 0) {
        throw '登录后双端点状态异常'
    }
    $peerCode = Logged $peer @('campus-run', '-config', $testConfig, '-key', (Join-Path $private 'peer.key'),
        '-result', (Join-Path $results 'campus-summary.json'), '-run-id', $runId) (Join-Path $results 'campus-run.log')
    $traffic = $null
    if (Test-Path -LiteralPath (Join-Path $results 'campus-summary.json')) {
        $traffic = Get-Content -LiteralPath (Join-Path $results 'campus-summary.json') -Raw | ConvertFrom-Json
        foreach ($check in $traffic.checks) {
            if ($check.passed) { Record $check.name } else {
                ('FAIL ' + $check.name + '; category=' + $check.error_category) | Out-File -LiteralPath $summary -Append -Encoding utf8
            }
        }
    }
    if ($peerCode -ne 0 -or $null -eq $traffic -or -not $traffic.passed) { throw '真实流量或生命周期检查失败' }
    Record 'campus-suite-complete'
} catch {
    $failed = $true
    $line = 'FAIL ' + $stage + '; ' + $_.Exception.Message
    Write-Host $line
    $line | Out-File -LiteralPath $summary -Append -Encoding utf8
    $_ | Format-List * -Force | Out-File -LiteralPath (Join-Path $results 'failure.log') -Encoding utf8
} finally {
    if ($owned) {
        $stage = 'cleanup-owned-instance'
        try {
            if ((Logged $peer @('campus-close', '-config', $testConfig, '-result', (Join-Path $results 'cleanup.json')) (Join-Path $results 'cleanup.log')) -ne 0) {
                throw '独立服务未完整关闭'
            }
            if ($null -ne $daemonProcess -and -not $daemonProcess.WaitForExit(5000)) { throw '服务进程未在期限内退出' }
            Record 'service-stopped-and-process-exited'
        } catch {
            $failed = $true
            ('FAIL cleanup; ' + $_.Exception.Message) | Out-File -LiteralPath $summary -Append -Encoding utf8
        }
        if ($null -ne $daemonProcess) { $daemonProcess.Dispose() }
        if ($privateHash -ne '' -and (Get-FileHash -LiteralPath $testConfig -Algorithm SHA256).Hash -eq $privateHash) {
            Record 'private-config-identity-stable'
        } elseif ($privateHash -ne '') {
            $failed = $true
            'FAIL private-config-changed' | Out-File -LiteralPath $summary -Append -Encoding utf8
        }
        # 只复制这次副本的原始日志，固定最多三个文件；不采集其他实例。
        if (Test-Path -LiteralPath (Join-Path $results 'cleanup.json')) {
            $cleanup = Get-Content -LiteralPath (Join-Path $results 'cleanup.json') -Raw | ConvertFrom-Json
            foreach ($suffix in @('', '.1', '.2')) {
                $log = Join-Path $private ('njuvpn-' + $cleanup.instance_tag + '-config.log' + $suffix)
                if (Test-Path -LiteralPath $log -PathType Leaf) {
                    Copy-Item -LiteralPath $log -Destination (Join-Path $results ('daemon.log' + $suffix))
                }
            }
        }
    }
    if ((Get-FileHash -LiteralPath $ConfigPath -Algorithm SHA256).Hash -eq $originalHash) {
        Record 'original-config-unchanged'
    } else {
        $failed = $true
        'FAIL original-config-changed' | Out-File -LiteralPath $summary -Append -Encoding utf8
    }
    ('completed_utc=' + [DateTime]::UtcNow.ToString('o')) | Out-File -LiteralPath $summary -Append -Encoding utf8
}
Compress-Archive -LiteralPath $results -DestinationPath ($results + '.zip')
Write-Host ('请回传：' + $results + '.zip')
Write-Host ('私有配置与密钥仍在本机：' + $private)
if ($failed) { exit 1 }
