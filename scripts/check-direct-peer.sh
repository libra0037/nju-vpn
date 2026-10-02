#!/usr/bin/env bash
# 独立测试对端只支持本轮实机的 Linux/amd64、Windows/amd64；无构建标签。
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/toolchain.sh
if [[ $(go env GOVERSION) != "go$GO_VERSION" ]]; then
  echo "要求 Go $GO_VERSION" >&2
  exit 1
fi
cd scripts/release-test/direct-peer
if [[ $(go list -m -f '{{.GoVersion}}') != "$GO_VERSION" ]]; then
  echo '测试模块的 Go 版本须与产品一致' >&2
  exit 1
fi
native=$(go env GOOS)/$(go env GOARCH)
case "$native" in
  linux/amd64|windows/amd64) ;;
  *) echo "此测试工具未声明支持 $native" >&2; exit 1 ;;
esac
formatted=$(gofmt -l .)
if [[ -n $formatted ]]; then echo "$formatted"; exit 1; fi
go vet ./...
go mod tidy -diff
output=$(mktemp -d)
trap 'rm -r "$output"' EXIT
for target in linux/amd64 windows/amd64; do
  CGO_ENABLED=0 GOOS=${target%/*} GOARCH=${target#*/} go build -trimpath -o "$output/test-peer-${target//\//-}" .
done
CGO_ENABLED=1 go test -race -count=1 -timeout=2m ./...
"$(go env GOPATH)/bin/staticcheck" ./...
"$(go env GOPATH)/bin/deadcode" -filter 'github.com/libra0037/nju-vpn/scripts/release-test/direct-peer' .
echo '直接对端检查全部通过'
