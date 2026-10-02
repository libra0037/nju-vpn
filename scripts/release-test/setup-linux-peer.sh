#!/usr/bin/env bash
# 只重配用户已指定为专用测试接口的 wgtest；保留原配置以供人工恢复。
set -euo pipefail
source "$(dirname "$0")/target.sh"
private=${1:?用法: sudo bash setup-linux-peer.sh /绝对路径/private-peer-xxxxxx}
if [[ $EUID != 0 ]]; then echo '需要 sudo' >&2; exit 1; fi
umask 077
# 目标也是维护者的 SSH 来源；只为测试协议/端口走独立路由表。
# 优先级 21121 必须早于 main（32766）；已有同号规则或表则拒绝覆盖。
if ip rule show | awk '$1 == "21121:" {found=1} END {exit !found}'; then
  echo '路由优先级 21121 已被使用，请先清理本测试配置' >&2
  exit 1
fi
if [[ -n $(ip route show table 61121 2>/dev/null) ]]; then
  echo '路由表 61121 已被使用，拒绝覆盖' >&2
  exit 1
fi
if ip link show wgtest >/dev/null 2>&1; then
  if [[ ! -e "$private/wgtest-before.conf" ]]; then
    wg showconf wgtest > "$private/wgtest-before.conf"
    ip -json address show dev wgtest > "$private/wgtest-before-address.json"
    ip route show dev wgtest > "$private/wgtest-before-routes.txt"
  fi
  ip link delete wgtest
fi
peer_address=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["peer_address"])' "$private/info.json")
ip link add wgtest type wireguard
ip link set wgtest mtu 1400
ip address add "$peer_address/32" dev wgtest
wg setconf wgtest "$private/peer.conf"
ip link set wgtest up
ip route add "$test_target/32" dev wgtest table 61121
ip rule add priority 21121 to "$test_target/32" ipproto tcp dport 18080 lookup 61121
ip rule add priority 21121 to "$test_target/32" ipproto udp dport 18081 lookup 61121
ip rule add priority 21121 to "$test_target/32" ipproto icmp lookup 61121
printf 'wgtest 已配置，MTU 1400；只路由测试 HTTP、UDP 与 ICMP，保留 SSH 路由。\n'
