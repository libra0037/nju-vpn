# Windows 10 / PowerShell 5.1；默认只运行离线用例。
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$OutputEncoding = [Text.Encoding]::UTF8
Set-Location $PSScriptRoot
foreach ($line in Get-Content -LiteralPath (Join-Path $PSScriptRoot 'SHA256SUMS')) {
    if ($line -notmatch '^([a-f0-9]{64})  (.+)$') { throw '校验清单格式错误' }
    $expected = $Matches[1]
    $path = Join-Path $PSScriptRoot $Matches[2]
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) {
        throw '测试包文件校验失败'
    }
}
$results = Join-Path $PSScriptRoot ('results-offline-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $results | Out-Null
$summary = Join-Path $results 'summary.txt'
@("os=$([Environment]::OSVersion.VersionString)", "process_arch=$env:PROCESSOR_ARCHITECTURE") |
    Out-File -LiteralPath $summary -Encoding utf8
& (Join-Path $PSScriptRoot 'njuvpn.exe') version | Out-File -LiteralPath $summary -Append -Encoding utf8
Get-Content -LiteralPath (Join-Path $PSScriptRoot 'BUILD.txt') | Out-File -LiteralPath $summary -Append -Encoding utf8
'Windows race 未包含在本测试包，须另在原生 Go/CGO 环境验证。' | Out-File -LiteralPath $summary -Append -Encoding utf8
$oldBinary = $env:NJUVPN_TEST_BINARY
$env:NJUVPN_TEST_BINARY = Join-Path $PSScriptRoot 'njuvpn.exe'
$failed = $false
# Go 的目录句柄恢复在 WSL 的 UNC 共享上失败；测试工作目录使用本机磁盘。
Push-Location $env:TEMP
try {
    foreach ($test in Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'tests') -Filter '*.test.exe') {
        $log = Join-Path $results ($test.Name + '.log')
        Write-Host ($test.Name + ' ... ') -NoNewline
        $ErrorActionPreference = 'Continue'
        & $test.FullName '-test.v' '-test.timeout=3m' 2>&1 |
            ForEach-Object { "$_" } | Out-File -LiteralPath $log -Encoding utf8
        $code = $LASTEXITCODE
        $ErrorActionPreference = 'Stop'
        if ($code -eq 0) { $result = 'PASS' } else { $result = 'FAIL'; $failed = $true }
        Write-Host $result
        ($result + ' ' + $test.Name) | Out-File -LiteralPath $summary -Append -Encoding utf8
        Select-String -LiteralPath $log -Pattern '^--- SKIP:' |
            ForEach-Object { 'SKIP ' + $_.Line } | Out-File -LiteralPath $summary -Append -Encoding utf8
    }
} finally {
    Pop-Location
    $env:NJUVPN_TEST_BINARY = $oldBinary
}
Get-Content -LiteralPath $summary
$archive = $results + '.zip'
Compress-Archive -LiteralPath $results -DestinationPath $archive
Write-Host ('请回传：' + $archive)
if ($failed) { exit 1 }
