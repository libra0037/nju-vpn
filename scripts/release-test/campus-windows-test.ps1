param([string]$ScriptPath = '')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($ScriptPath -eq '') { $ScriptPath = Join-Path $PSScriptRoot 'campus-windows.ps1' }
$ScriptPath = (Resolve-Path -LiteralPath $ScriptPath).ProviderPath
# Linux 上的 PowerShell 7 检查不替代 5.1 参数绑定，直接守卫这次已确认的误用。
foreach ($path in @($PSCommandPath, $ScriptPath)) {
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -ne 0) { throw ('脚本语法错误: ' + $path) }
    foreach ($parameter in $ast.ParamBlock.Parameters) {
        if ($null -eq $parameter.DefaultValue) { continue }
        $usesScriptRoot = @($parameter.DefaultValue.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.VariableExpressionAst] -and
                $node.VariablePath.UserPath -eq 'PSScriptRoot'
        }, $true))
        if ($usesScriptRoot.Count -ne 0) { throw ('参数默认值不得读取 PSScriptRoot: ' + $path) }
    }
}
Write-Output 'PASS 校园 Windows 参数默认值守卫'
$root = Join-Path ([IO.Path]::GetTempPath()) ('njuvpn-campus-wrapper-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
$priorTarget = [Environment]::GetEnvironmentVariable('NJUVPN_TEST_TARGET_IP')
$commands = @()
# 只模拟候选程序与 Go 工具的外部结果；脚本本体、文件操作、摘要与 ZIP 实际执行。
# 内置命令的假实现随脚本作用域释放；完整路径的假程序须进入全局命令表并在 finally 删除。
function Get-FileHash {
    param([string]$LiteralPath, [string]$Algorithm)
    if ($LiteralPath -eq $global:CampusWrapperFixture.binary) {
        return [pscustomobject]@{ Hash = '7508e6b469f0b1d86f877a3d4a983a2bad7f98a214f9831a1b60cc9f809a3627' }
    }
    Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $LiteralPath -Algorithm $Algorithm
}
function Get-Process {
    param([int]$Id)
    if ($Id -ne 4242 -or -not $global:CampusWrapperFixture.created) { throw '脚本等待了其他实例' }
    $process = [pscustomobject]@{ Id = 4242 }
    $process | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value {
        param([int]$Milliseconds)
        if ($Milliseconds -ne 5000) { throw '进程等待没有固定上限' }
        return $global:CampusWrapperFixture.closed
    }
    $process | Add-Member -MemberType ScriptMethod -Name Dispose -Value { $global:CampusWrapperFixture.disposed = $true }
    return $process
}
function Get-FixtureArgument([object[]]$Options, [string]$Name) {
    $index = [Array]::IndexOf($Options, $Name)
    if ($index -lt 0 -or $index + 1 -ge $Options.Count) { throw '缺少固定参数' }
    return $Options[$index + 1]
}
try {
    $env:NJUVPN_TEST_TARGET_IP = '192.0.2.1'
    foreach ($case in @('pass-default', 'pass-explicit', 'native-fail', 'prepare-fail', 'login-fail', 'traffic-fail', 'missing-result', 'cleanup-fail')) {
        $successful = $case -in @('pass-default', 'pass-explicit')
        $directory = Join-Path $root ($case + ' 中文 空格')
        $package = Join-Path $directory 'windows-campus-test'
        New-Item -ItemType Directory -Path $package -Force | Out-Null
        Copy-Item -LiteralPath $ScriptPath -Destination (Join-Path $package 'campus-windows.ps1')
        Copy-Item -LiteralPath (Join-Path (Split-Path -Parent $ScriptPath) 'target.ps1') -Destination $package
        $bundle = $directory
        if ($case -eq 'pass-explicit') {
            $bundle = Join-Path $directory '显式 程序目录'
            New-Item -ItemType Directory -Path $bundle | Out-Null
        }
        $binary = Join-Path $bundle 'njuvpn.exe'
        $peer = Join-Path $package 'test-peer-campus.exe'
        $nativeTests = Join-Path $package 'campus.test.exe'
        $source = Join-Path $directory 'existing.yaml'
        foreach ($file in @($binary, $peer, $nativeTests)) { [IO.File]::WriteAllText($file, '固定离线样例') }
        [IO.File]::WriteAllText($source, "device_id: fixed-device`npassword: '  fixed password  '`n")
        [IO.File]::WriteAllText((Join-Path $package 'BUILD.txt'), 'fixture=offline-wrapper')
        $hashes = foreach ($file in @($peer, $nativeTests)) {
            (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + (Split-Path -Leaf $file)
        }
        $hashes | Out-File -LiteralPath (Join-Path $package 'SHA256SUMS') -Encoding ascii
        $before = (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
        $global:CampusWrapperFixture = @{ binary = $binary; source = $source; case = $case; created = $false;
            started = $false; closed = $false; disposed = $false; config = ''; log_hash = ''; calls = [Collections.Generic.List[string]]::new() }
        $commands += @($binary, $peer, $nativeTests)
        Set-Item -LiteralPath ('function:global:' + $nativeTests) -Value {
            $global:CampusWrapperFixture.calls.Add('native-tests')
            $global:LASTEXITCODE = if ($global:CampusWrapperFixture.case -eq 'native-fail') { 1 } else { 0 }
            Write-Output '固定原生用例结果'
        }
        Set-Item -LiteralPath ('function:global:' + $binary) -Value {
            $state = $global:CampusWrapperFixture
            $state.calls.Add([string]$args[0])
            $config = Get-FixtureArgument $args '-config'
            if ($config -ne $state.config -or $config -eq $state.source) { throw '操作打到了原实例' }
            $global:LASTEXITCODE = 0
            switch ($args[0]) {
                'restart' { $state.created = $true; Write-Output '固定启动结果' }
                'start' {
                    $global:LASTEXITCODE = if ($state.case -eq 'login-fail') { 1 } else { 0 }
                    $state.started = $global:LASTEXITCODE -eq 0
                }
                'status' {
                    @{ state = $(if ($state.started) { 'up' } else { 'idle' }); identity = @{ pid = 4242 } } | ConvertTo-Json -Compress
                    if (-not $state.started) { $global:LASTEXITCODE = 4 }
                }
                default { throw '出现未授权的候选程序命令' }
            }
        }
        Set-Item -LiteralPath ('function:global:' + $peer) -Value {
            $state = $global:CampusWrapperFixture
            $state.calls.Add([string]$args[0])
            $global:LASTEXITCODE = 0
            switch ($args[0]) {
                'campus-prepare' {
                    if ($state.case -eq 'prepare-fail') { $global:LASTEXITCODE = 1; return }
                    $out = Get-FixtureArgument $args '-out'
                    New-Item -ItemType Directory -Path $out | Out-Null
                    $state.config = Join-Path $out 'config.yaml'
                    Copy-Item -LiteralPath $state.source -Destination $state.config
                    [IO.File]::WriteAllText((Join-Path $out 'peer.key'), 'fixed-key')
                }
                'campus-run' {
                    $result = Get-FixtureArgument $args '-result'
                    if ($state.case -eq 'missing-result') { return }
                    $passed = $state.case -ne 'traffic-fail'
                    @{ passed = $passed; checks = @(@{ name = 'fixed-campus-check'; passed = $passed; error_category = 'fixture' }) } |
                        ConvertTo-Json -Depth 4 | Out-File -LiteralPath $result -Encoding utf8
                    if (-not $passed) { $global:LASTEXITCODE = 1 }
                }
                'campus-close' {
                    if (-not $state.created) { throw '关闭了不属于脚本的实例' }
                    $state.closed = $true
                    $result = Get-FixtureArgument $args '-result'
                    @{ service_stopped = $true; instance_tag = '0123456789abcdef0123456789abcdef' } |
                        ConvertTo-Json | Out-File -LiteralPath $result -Encoding utf8
                    $log = Join-Path (Split-Path -Parent $state.config) 'njuvpn-0123456789abcdef0123456789abcdef-config.log'
                    [IO.File]::WriteAllText($log, '固定原始日志：raw-fixture')
                    $state.log_hash = (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $log -Algorithm SHA256).Hash
                    if ($state.case -eq 'cleanup-fail') { $global:LASTEXITCODE = 1 }
                }
                default { throw '出现未授权的工具命令' }
            }
        }
        $global:LASTEXITCODE = 0
        $options = @{ ConfigPath = $source }
        if ($case -eq 'pass-explicit') { $options.BundlePath = $bundle }
        & (Join-Path $package 'campus-windows.ps1') @options
        $exitCode = $LASTEXITCODE
        if (($exitCode -eq 0) -ne $successful) { throw ('退出码判据错误: ' + $case) }
        $archives = @(Get-ChildItem -LiteralPath $package -Filter 'results-campus-*.zip')
        if ($archives.Count -ne 1) { throw '没有在成功或失败后生成唯一回传包' }
        $unpacked = Join-Path $directory 'unpacked'
        Expand-Archive -LiteralPath $archives[0].FullName -DestinationPath $unpacked
        $summary = @(Get-ChildItem -LiteralPath $unpacked -Filter 'summary.txt' -Recurse)
        if ($summary.Count -ne 1 -or (Get-Content -LiteralPath $summary[0].FullName -Raw) -notmatch 'PASS original-config-unchanged') { throw '原配置守卫没有留下结果' }
        if ((Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne $before) { throw '原配置被改动' }
        $state = $global:CampusWrapperFixture
        if ($state.created -and (-not $state.closed -or -not $state.disposed)) { throw '失败后没有关闭并释放自己的进程句柄' }
        if (-not $state.created -and $state.calls.Contains('campus-close')) { throw '关闭了不属于脚本的实例' }
        if ($successful) {
            $actual = [string]::Join(',', $state.calls)
            if ($actual -ne 'native-tests,campus-prepare,restart,status,start,status,campus-run,campus-close') { throw '完整流程命令顺序错误' }
            $logs = @(Get-ChildItem -LiteralPath $unpacked -Filter 'daemon.log' -Recurse)
            # 守卫复制前后的字节；默认文本解码随 PowerShell 版本和系统代码页变化。
            if ($logs.Count -ne 1 -or (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $logs[0].FullName -Algorithm SHA256).Hash -ne $state.log_hash) { throw '本实例原始日志丢失或改写' }
        }
        Write-Output ('PASS 校园 Windows 编排离线用例: ' + $case)
    }
} finally {
    # 用提供者限定路径保留假命令的完整名字，避免盘符或前导斜线参与驱动路径归一。
    foreach ($name in $commands) { Remove-Item -LiteralPath ('Function::' + $name) -ErrorAction SilentlyContinue }
    Remove-Variable -Name CampusWrapperFixture -Scope Global -ErrorAction SilentlyContinue
    [Environment]::SetEnvironmentVariable('NJUVPN_TEST_TARGET_IP', $priorTarget)
    Remove-Item -LiteralPath $root -Recurse -Force
}
# 预期失败用例的原生命令退出码不代表整份守卫失败。
$global:LASTEXITCODE = 0
