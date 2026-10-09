#!/usr/bin/env bash
# 实机测试会登录、断开 VPN；只回传结果摘要，原始输出留在私有目录。
set -euo pipefail
source "$(dirname "$0")/target.sh"
cd "$(dirname "$0")"
config=${1:?用法: bash live-linux.sh /绝对路径/测试配置.yaml}
config=$(realpath "$config")
# 排障时只替换被测程序，保持资源查询、重复 start 和数据测试顺序相同。
binary=$(realpath "${2:-$PWD/njuvpn}")
umask 077
results=$(mktemp -d "$PWD/results-live-XXXXXX")
private=$(mktemp -d "$(dirname "$config")/private-live-XXXXXX")
summary="$results/summary.txt"
"$binary" version > "$summary"
cat BUILD.txt >> "$summary"
binary_hash=$(sha256sum "$binary")
printf 'binary_sha256=%s\n' "${binary_hash%% *}" >> "$summary"
state=$(./test-helper state -config "$config" 2>/dev/null || true)
if [[ -n $state && $state != idle ]]; then
  echo '测试实例已有活动会话，请先停止再运行脚本' >&2
  exit 1
fi
cleanup() {
  "$binary" stop -config "$config" >> "$private/cleanup.log" 2>&1 || true
  ./test-helper shutdown -config "$config" >> "$private/cleanup.log" 2>&1 || true
  printf '结果摘要：%s\n原始输出（不要回传）：%s\n' "$results" "$private"
}
trap cleanup EXIT
check() {
  local name=$1; shift
  if "$@" > "$private/$name.log" 2>&1; then
    printf 'PASS %s\n' "$name" | tee -a "$summary"
  else
    printf 'FAIL %s\n' "$name" | tee -a "$summary"
    exit 1
  fi
}
check baseline python3 live-probe.py baseline
check initialize "$binary" restart -config "$config"
./test-helper info -config "$config" > "$private/before.json"
check start "$binary" start -config "$config"
check status "$binary" status -json -config "$config"
check resources-json ./test-helper resources -config "$config"
cp "$private/resources-json.log" "$results/resources-summary.json"
check resources-cli "$binary" resources -config "$config"
python3 - "$private" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1])
info = json.loads((p / 'resources-json.log').read_text())
rules = info['ip_rules'] + info['tcp_domains']
if len((p / 'resources-cli.log').read_text().splitlines()) != rules + 6 or rules == 0:
    raise SystemExit('资源打印行数不完整或资源表为空')
PY
check repeat-start "$binary" start -config "$config"
check repeat-status "$binary" status -json -config "$config"
# 握手就绪与丢包计数会异步变化；幂等判据只比较实例与状态进入时间。
python3 - "$private" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1])
a = json.loads((p / 'status.log').read_text())
b = json.loads((p / 'repeat-status.log').read_text())
if a['state'] != 'up' or b['state'] != 'up' or a.get('retrying') or b.get('retrying'):
    raise SystemExit('重复 start 后校园链路未就绪')
if (a['identity'], a['since']) != (b['identity'], b['since']):
    raise SystemExit('重复 start 改变了实例或重新进入 up 状态')
PY
check resources-repeat ./test-helper resources -config "$config"
cmp "$private/resources-json.log" "$private/resources-repeat.log"
check online python3 live-probe.py online
cp "$private/online.log" "$results/traffic-summary.json"
check mtu-1400 ping -n -I wgtest -M do -s 1372 -c 3 -W 30 "$test_target"
check heartbeat-survival bash -c 'sleep 50; "$1" status -config "$2"' _ "$binary" "$config"
check stop "$binary" stop -config "$config"
status_code=0
"$binary" status -config "$config" > "$private/stopped-status.log" 2>&1 || status_code=$?
if [[ $status_code != 4 ]]; then
  printf 'FAIL stopped-status\n' | tee -a "$summary"
  exit 1
fi
check stopped python3 live-probe.py stopped
./test-helper info -config "$config" > "$private/after.json"
cmp "$private/before.json" "$private/after.json"
printf 'PASS resource-row-count resource-repeat start-idempotent identity-stable stopped-status\n' | tee -a "$summary"
