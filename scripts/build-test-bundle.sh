#!/usr/bin/env bash
# 构建不含凭据、无需目标机器安装 Go 的发布前测试包。
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/toolchain.sh
version=${1:?用法: bash scripts/build-test-bundle.sh v0.1.1 [输出目录]}
out=${2:-dist/test-$version-$(date -u +%Y%m%dT%H%M%SZ)}
if [[ $(go env GOVERSION) != "go$GO_VERSION" ]]; then
  echo "要求 Go $GO_VERSION" >&2
  exit 1
fi
if [[ -e "$out" ]]; then
  echo "输出目录已经存在，拒绝覆盖：$out" >&2
  exit 1
fi
mkdir -p "$out"
out=$(cd "$out" && pwd)
umask 077
module=$(go list -m)
# 列包失败必须终止；进程替换不会把子命令的失败传给 mapfile。
package_list=$(go list -tags "$BUILD_TAGS" -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}' ./... | rg .)
mapfile -t packages <<< "$package_list"
# 只登记 Git 接纳的公开文件；rg 的正向 glob 会重新纳入被忽略的 REVIEW.md。
git ls-files --cached --others --exclude-standard -z | python3 -c '
import sys
for path in sys.stdin.buffer.read().split(b"\0"):
    if path and (path.endswith((b".go", b".mod", b".sum", b".sh", b".ps1", b".py", b".md")) or path in (b"config.example.yaml", b".gitignore") or path.startswith(b".github/workflows/")):
        sys.stdout.buffer.write(path + b"\0")
' |
  LC_ALL=C sort -z | xargs -0 sha256sum > "$out/SOURCE-SHA256SUMS"
source_hash=$(sha256sum "$out/SOURCE-SHA256SUMS")
source_hash=${source_hash%% *}
printf 'version=%s\ngo=%s\nbuild_tags=%s\nsource_sha256=%s\nhead=%s\n' \
  "$version" "$GO_VERSION" "$BUILD_TAGS" "$source_hash" "$(git rev-parse HEAD)" > "$out/BUILD.txt"

# 构建目标仍取唯一的平台清单；本次实机为 Linux 与 Windows x64。
for target in linux/amd64 windows/amd64; do
  supported=false
  for entry in "${PLATFORMS[@]}"; do
    if [[ ${entry%:*} == "$target" ]]; then supported=true; fi
  done
  if ! "$supported"; then echo "不支持的目标：$target" >&2; exit 1; fi
  goos=${target%/*}
  goarch=${target#*/}
  ext=''
  if [[ $goos == windows ]]; then ext=.exe; fi
  bundle="$out/njuvpn-test-$version-$goos-$goarch"
  mkdir -p "$bundle/tests"
  cp config.example.yaml "$bundle/config.example.yaml"
  cp "$out/BUILD.txt" "$bundle/BUILD.txt"
  cp scripts/release-test/README.md "$bundle/README.md"
  GOOS=$goos GOARCH=$goarch CGO_ENABLED=0 go build -tags "$BUILD_TAGS" \
    -trimpath -ldflags "-s -w -X main.version=$version" -o "$bundle/njuvpn$ext" ./cmd/njuvpn
  GOOS=$goos GOARCH=$goarch CGO_ENABLED=0 go build -trimpath -o "$bundle/test-helper$ext" scripts/release-test/helper.go
  (cd scripts/release-test/direct-peer && GOOS=$goos GOARCH=$goarch CGO_ENABLED=0 go build -trimpath -o "$bundle/test-peer$ext" .)
  for pkg in "${packages[@]}"; do
    name=${pkg#$module/}
    name=${name//\//_}
    GOOS=$goos GOARCH=$goarch CGO_ENABLED=0 go test -c -tags "$BUILD_TAGS" -trimpath \
      -o "$bundle/tests/$name.test$ext" "$pkg"
  done
  if [[ $goos == linux ]]; then
    cp scripts/release-test/run-linux.sh scripts/release-test/live-linux.sh scripts/release-test/prepare-linux-peer.sh scripts/release-test/setup-linux-peer.sh scripts/release-test/cleanup-linux-peer.sh scripts/release-test/live-probe.py scripts/release-test/target.sh scripts/release-test/target_ip.py "$bundle/"
    chmod +x "$bundle/"*.sh
    # race 产物依赖 libc；仅在本机目标一致时生成，并在服务器上检查可运行性。
    if [[ $(go env GOOS)/$(go env GOARCH) == "$target" ]]; then
      mkdir -p "$bundle/race"
      for pkg in "${packages[@]}"; do
        name=${pkg#$module/}
        name=${name//\//_}
        CGO_ENABLED=1 go test -c -race -tags "$BUILD_TAGS" -trimpath -o "$bundle/race/$name.test" "$pkg"
      done
    fi
  else
    cp scripts/release-test/target.ps1 "$bundle/target.ps1"
    # Windows PowerShell 5.1 用 BOM 识别 UTF-8 中文脚本。
    printf '\357\273\277' > "$bundle/run-windows.ps1"
    cat scripts/release-test/run-windows.ps1 >> "$bundle/run-windows.ps1"
    printf '\357\273\277' > "$bundle/live-windows.ps1"
    cat scripts/release-test/live-windows.ps1 >> "$bundle/live-windows.ps1"
    printf '\357\273\277' > "$bundle/direct-windows.ps1"
    cat scripts/release-test/direct-windows.ps1 >> "$bundle/direct-windows.ps1"
    printf '\357\273\277' > "$bundle/resilience-windows.ps1"
    cat scripts/release-test/resilience-windows.ps1 >> "$bundle/resilience-windows.ps1"
  fi
  (cd "$bundle" && find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS)
  if [[ $goos == windows ]]; then
    (cd "$out" && python3 - "$bundle" <<'PY'
import pathlib, sys, zipfile
root = pathlib.Path(sys.argv[1])
with zipfile.ZipFile(root.name + '.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
    for path in sorted(root.rglob('*')):
        if path.is_file():
            archive.write(path, path.relative_to(root.parent))
PY
    )
  else
    tar -czf "$bundle.tar.gz" -C "$out" "$(basename "$bundle")"
  fi
  echo "$bundle"
done
