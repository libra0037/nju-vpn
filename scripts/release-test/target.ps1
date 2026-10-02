function Get-TestTarget {
    $value = [Environment]::GetEnvironmentVariable('NJUVPN_TEST_TARGET_IP')
    $address = $null
    if ([string]::IsNullOrEmpty($value) -or $value.Length -gt 15 -or
        -not [Net.IPAddress]::TryParse($value, [ref]$address) -or
        $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
        $address.ToString() -ne $value -or [Net.IPAddress]::IsLoopback($address) -or
        $address.Equals([Net.IPAddress]::Any) -or $address.GetAddressBytes()[0] -ge 224) {
        throw '需设置 NJUVPN_TEST_TARGET_IP 为有效的非回环 IPv4 地址'
    }
    return $address.ToString()
}
