$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
# CI 在同一 PowerShell 进程中执行守卫；每份守卫的假命令须随其作用域释放。
foreach ($name in @('campus-windows-test.ps1', 'run-windows-test.ps1')) {
    $scriptPath = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot $name)).ProviderPath
    $global:LASTEXITCODE = 0
    & $scriptPath
    if (-not $?) { throw ('编排守卫执行失败: ' + $name) }
    if ($LASTEXITCODE -ne 0) { throw ('编排守卫退出状态错误: ' + $name) }
    # 按定义所属文件识别泄漏，既检查固定命令，也检查动态生成的假程序命令。
    $remaining = @(Get-ChildItem function: | Where-Object { $_.ScriptBlock.File -eq $scriptPath })
    if ($remaining.Count -ne 0) { throw ('编排守卫的假命令没有释放: ' + $name) }
    Write-Output ('PASS Windows 编排假命令收尾: ' + $name)
}
$global:LASTEXITCODE = 0
