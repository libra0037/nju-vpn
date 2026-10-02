#!/usr/bin/env bash
# 只删除本测试添加的精确规则和专用接口。
set -euo pipefail
source "$(dirname "$0")/target.sh"
if [[ $EUID != 0 ]]; then echo '需要 sudo' >&2; exit 1; fi
ip rule del priority 21121 to "$test_target/32" ipproto tcp dport 18080 lookup 61121 2>/dev/null || true
ip rule del priority 21121 to "$test_target/32" ipproto udp dport 18081 lookup 61121 2>/dev/null || true
ip rule del priority 21121 to "$test_target/32" ipproto icmp lookup 61121 2>/dev/null || true
ip route del "$test_target/32" dev wgtest table 61121 2>/dev/null || true
ip link delete wgtest
