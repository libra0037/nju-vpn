$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$source = Join-Path $PSScriptRoot 'run-windows.ps1'
$root = Join-Path ([IO.Path]::GetTempPath()) ('njuvpn-offline-wrapper-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
$priorTemp = $env:TEMP
$priorBinary = $env:NJUVPN_TEST_BINARY
$priorRace = $env:GORACE
$commands = @()
Push-Location
try {
    $env:TEMP = $root
    foreach ($case in @('pass', 'race-fail')) {
        $package = Join-Path $root ($case + ' 中文 空格')
        $tests = Join-Path $package 'tests'
        New-Item -ItemType Directory -Path $tests -Force | Out-Null
        $script = Join-Path $package 'run-windows.ps1'
        # 组包入口用 BOM 标识 UTF-8；这里按同一外部文件契约执行实际脚本。
        [IO.File]::WriteAllText($script, [IO.File]::ReadAllText($source), [Text.UTF8Encoding]::new($true))
        $binary = Join-Path $package 'njuvpn.exe'
        $first = Join-Path $tests 'first.test.exe'
        $second = Join-Path $tests 'second.test.exe'
        foreach ($path in @($binary, $first, $second)) { [IO.File]::WriteAllText($path, '固定离线样例') }
        [IO.File]::WriteAllText((Join-Path $package 'BUILD.txt'), 'test_mode=race')
        $hashes = foreach ($path in @($binary, $first, $second)) {
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + $path.Substring($package.Length + 1).Replace('\', '/')
        }
        $hashes | Out-File -LiteralPath (Join-Path $package 'SHA256SUMS') -Encoding ascii
        $global:OfflineWrapperFixture = @{ case = $case; binary = $binary; observed = 0 }
        # 完整路径的调用需要全局假命令；每个名字属于本轮临时目录，finally 显式释放。
        $commands += @($binary, $first, $second)
        Set-Item -LiteralPath ('function:global:' + $binary) -Value {
            if ($args.Count -ne 1 -or $args[0] -ne 'version') { throw '候选程序命令不符' }
            $global:LASTEXITCODE = 0
            Write-Output 'fixture-version'
        }
        foreach ($path in @($first, $second)) {
            Set-Item -LiteralPath ('function:global:' + $path) -Value {
                $state = $global:OfflineWrapperFixture
                if ($env:GORACE -ne 'log_path=stderr exitcode=66 halt_on_error=1' -or $env:NJUVPN_TEST_BINARY -ne $state.binary) {
                    throw '检测报告、失败退出或候选程序身份没有按执行契约设置'
                }
                $state.observed++
                $global:LASTEXITCODE = if ($state.case -eq 'race-fail') { 66 } else { 0 }
                if ($state.case -eq 'race-fail') { Write-Output 'WARNING: DATA RACE' }
                Write-Output '    --- SKIP: TestFixedBoundary/symlink (0.00s)'
            }
        }
        $env:NJUVPN_TEST_BINARY = 'prior-binary'
        $env:GORACE = 'log_path=prior-file exitcode=0'
        $global:LASTEXITCODE = 0
        & $script
        if (($LASTEXITCODE -eq 0) -ne ($case -eq 'pass')) { throw '检测到数据竞争后没有使整轮失败' }
        if ($env:GORACE -ne 'log_path=prior-file exitcode=0' -or $env:NJUVPN_TEST_BINARY -ne 'prior-binary') { throw '没有恢复调用者环境' }
        if ($global:OfflineWrapperFixture.observed -ne 2) { throw '没有执行全部包' }
        $archives = @(Get-ChildItem -LiteralPath $package -Filter 'results-offline-*.zip')
        if ($archives.Count -ne 1) { throw '没有生成唯一回传 ZIP' }
        $unpacked = Join-Path $package 'unpacked'
        Expand-Archive -LiteralPath $archives[0].FullName -DestinationPath $unpacked
        $summary = @(Get-ChildItem -LiteralPath $unpacked -Filter 'summary.txt' -Recurse)
        if ($summary.Count -ne 1) { throw '缺少阶段汇总' }
        $text = Get-Content -LiteralPath $summary[0].FullName -Raw
        $result = if ($case -eq 'pass') { 'PASS' } else { 'FAIL' }
        foreach ($name in @('first.test.exe', 'second.test.exe')) {
            if (-not $text.Contains($result + ' ' + $name)) { throw '整轮结果与固定退出码不符' }
        }
        if ([regex]::Matches($text, 'SKIP .*TestFixedBoundary/symlink').Count -ne 2) { throw '嵌套 SKIP 未保留' }
        if ($case -eq 'race-fail') {
            $logs = @(Get-ChildItem -LiteralPath $unpacked -Filter '*.test.exe.log' -Recurse)
            if ($logs.Count -ne 2) { throw '缺少竞争报告日志' }
            foreach ($log in $logs) {
                if ((Get-Content -LiteralPath $log.FullName -Raw) -notmatch 'WARNING: DATA RACE') { throw '竞争报告未保留' }
            }
        }
        Write-Output ('PASS Windows 离线编排守卫: ' + $case)
    }
} finally {
    Pop-Location
    $env:TEMP = $priorTemp
    $env:NJUVPN_TEST_BINARY = $priorBinary
    $env:GORACE = $priorRace
    foreach ($name in $commands) { Remove-Item -LiteralPath ('Function::' + $name) -ErrorAction SilentlyContinue }
    Remove-Variable -Name OfflineWrapperFixture -Scope Global -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $root -Recurse -Force
}
# 预期失败用例的原生命令退出码不代表整份守卫失败。
$global:LASTEXITCODE = 0
