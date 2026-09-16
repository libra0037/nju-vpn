#!/usr/bin/env bash
# 构建发行版本：交叉编译各平台的二进制并生成校验和。
#
# 用法: scripts/build-release.sh v0.1.0
#
# 两个必须的构建参数：
#   -trimpath      不加的话，二进制里会嵌入本机的源码路径与用户名
#   -X main.version 把版本号注入 binary，用户可用 `njuvpn version` 确认
# CGO_ENABLED=0 让 Linux 产物静态链接，换台机器直接能跑。
set -euo pipefail

VERSION=${1:?用法: scripts/build-release.sh v0.1.0}
OUT=dist
PKG=./cmd/njuvpn

rm -rf "$OUT"
mkdir -p "$OUT"

build() {
  local goos=$1 goarch=$2 ext=${3:-}
  local name="njuvpn-${goos}-${goarch}${ext}"
  GOOS=$goos GOARCH=$goarch CGO_ENABLED=0 go build \
    -trimpath -ldflags "-s -w -X main.version=$VERSION" \
    -o "$OUT/$name" "$PKG"
  echo "  $name"
}

echo "构建 $VERSION"
build linux   amd64
build linux   arm64
build windows amd64 .exe
build windows arm64 .exe
# macOS 只保证能编译：本地没有机器实测过，遇到问题请开 issue。
build darwin  amd64
build darwin  arm64

( cd "$OUT" && sha256sum njuvpn-* > SHA256SUMS )

echo
echo "产物在 $OUT："
ls -lh "$OUT" | tail -n +2
