#!/usr/bin/env bash
# 默认只运行离线用例，不读取实机配置、不登录 VPN。
set -euo pipefail
cd "$(dirname "$0")"
umask 077
sha256sum --check --quiet SHA256SUMS
results=$(mktemp -d "$PWD/results-offline-XXXXXX")
export NJUVPN_TEST_BINARY="$PWD/njuvpn"
printf 'os=%s\narch=%s\n' "$(uname -s)" "$(uname -m)" > "$results/summary.txt"
./njuvpn version >> "$results/summary.txt"
cat BUILD.txt >> "$results/summary.txt"
failed=0
for mode in tests race; do
  [[ -d $mode ]] || continue
  for test in "$mode/"*.test; do
    [[ -f $test ]] || continue
    name=${test##*/}
    log="$results/$mode-$name.log"
    printf '%s/%s ... ' "$mode" "$name"
    if "$test" -test.v -test.timeout=3m > "$log" 2>&1; then
      printf 'PASS\n'
      printf 'PASS %s/%s\n' "$mode" "$name" >> "$results/summary.txt"
    else
      printf 'FAIL\n'
      printf 'FAIL %s/%s\n' "$mode" "$name" >> "$results/summary.txt"
      failed=1
    fi
    awk '/^--- SKIP:/{print "SKIP " $0}' "$log" >> "$results/summary.txt"
  done
done
cat "$results/summary.txt"
printf '结果目录：%s\n' "$results"
exit "$failed"
