#!/usr/bin/env bash
# 本地与 CI 共用的一套检查：格式、vet、交叉编译、测试、静态分析。
#
# 用法: scripts/check.sh
#
# staticcheck 不在 PATH 里时只跳过它并提醒一句：本地开发不该因为没装工具就
# 跑不了其余检查，而 CI 装了它就会真的跑。静态分析之外的三项是底线。
set -uo pipefail

fail=0

run() {
  echo "== $*"
  if ! "$@"; then
    fail=1
  fi
}

# gofmt -l 有输出就算失败（它列出的是没格式化的文件）。
fmt_out=$(gofmt -l . 2>&1)
if [ -n "$fmt_out" ]; then
  echo "== gofmt -l ."
  echo "$fmt_out"
  fail=1
fi

run go vet ./...
run go build ./...
# Windows 与 macOS 的分支在 Linux 上编译不到，交叉编译是它们唯一的守门人。
run env CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build ./...
run env CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build ./...
run go test ./... -race

if command -v staticcheck >/dev/null 2>&1; then
  run staticcheck ./...
else
  echo "== staticcheck 未安装，跳过（go install honnef.co/go/tools/cmd/staticcheck@2026.2.1）"
fi

if [ "$fail" -ne 0 ]; then
  echo
  echo "检查未通过"
  exit 1
fi
echo
echo "全部通过"

