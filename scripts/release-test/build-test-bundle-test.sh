#!/usr/bin/env bash
# 列包失败必须在生成构建标识和归档之前返回失败，防止空测试包被当成通过。
set -euo pipefail
cd "$(dirname "$0")/../.."
source scripts/toolchain.sh
test_dir=$(mktemp -d)
trap 'rm -r "$test_dir"' EXIT
mkdir "$test_dir/bin"
cat > "$test_dir/bin/go" <<'SH'
#!/usr/bin/env bash
case "$*" in
  'env GOVERSION') echo "go$NJUVPN_TEST_GO_VERSION" ;;
  'list -m') echo 'example.invalid/package-list-test' ;;
  *) echo 'test-package-list-failure' >&2; exit 42 ;;
esac
SH
chmod +x "$test_dir/bin/go"
if PATH="$test_dir/bin:$PATH" NJUVPN_TEST_GO_VERSION="$GO_VERSION" bash scripts/build-test-bundle.sh v0.1.1 "$test_dir/out" > "$test_dir/output" 2>&1; then
  echo '列包失败却返回成功' >&2
  exit 1
fi
if [[ -e "$test_dir/out/BUILD.txt" ]]; then
  echo '列包失败后仍继续构建' >&2
  exit 1
fi
grep -qF 'test-package-list-failure' "$test_dir/output"
echo 'PASS package-list failure stops before building or archiving'
