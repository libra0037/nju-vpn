package main

import (
	"errors"
	"net/netip"
	"os"
)

// 部署目标仅在命令入口读取；核心探测显式接收解析后的 IPv4 地址。
func targetFromEnvironment() (netip.Addr, error) {
	return parseTargetIP(os.Getenv("NJUVPN_TEST_TARGET_IP"))
}

func parseTargetIP(value string) (netip.Addr, error) {
	if len(value) == 0 || len(value) > 15 {
		return netip.Addr{}, errors.New("需设置 NJUVPN_TEST_TARGET_IP 为有效的非回环 IPv4 地址")
	}
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || address.IsLoopback() || address.IsUnspecified() || address.IsMulticast() || address.As4()[0] >= 224 {
		return netip.Addr{}, errors.New("NJUVPN_TEST_TARGET_IP 无效；只允许非回环 IPv4 地址")
	}
	return address, nil
}

func httpTarget(target netip.Addr) netip.AddrPort {
	return netip.AddrPortFrom(target, httpPort)
}
