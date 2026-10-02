$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'target.ps1')
$priorTarget = [Environment]::GetEnvironmentVariable('NJUVPN_TEST_TARGET_IP')
try {
    foreach ($invalid in @('', '::1', '127.0.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255', '192.0.2.1:80', '192.0.2.1/32', '192.0.2', '192.000.2.1', 'do-not-print-this-private-marker')) {
        $env:NJUVPN_TEST_TARGET_IP = $invalid
        $rejected = $false
        try { [void](Get-TestTarget) } catch {
            $rejected = $true
            if ($_.Exception.Message -ne '需设置 NJUVPN_TEST_TARGET_IP 为有效的非回环 IPv4 地址') {
                throw '目标拒绝错误回显了外部输入或丢失固定类别'
            }
        }
        if (-not $rejected) { throw '非法目标被接纳' }
    }
    foreach ($valid in @('192.0.2.1', '198.51.100.1', '10.0.0.1')) {
        $env:NJUVPN_TEST_TARGET_IP = $valid
        if ((Get-TestTarget) -ne $valid) { throw '有效目标被改变' }
    }
    Write-Output 'PASS explicit IPv4 target boundaries and redacted rejection'
} finally {
    [Environment]::SetEnvironmentVariable('NJUVPN_TEST_TARGET_IP', $priorTarget)
}
