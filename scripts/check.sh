#!/usr/bin/env bash
# 本地与 CI 共用的一套检查：格式、vet、打包平台、测试、静态分析、不可达分析，
# 外加文档命令与代码的一致性。
#
# 用法: scripts/check.sh
#
# 工具不在 PATH 里时会再到 $(go env GOPATH)/bin 找一次：go install 的默认落点
# 就在那里，漏掉这一条会把"其实装着"误判成"没装"而静默跳过检查。
set -uo pipefail

fail=0

run() {
  echo "== $*"
  if ! "$@"; then
    fail=1
  fi
}

# tool 打印工具的路径；找不到时打印空串。
tool() {
  if command -v "$1" >/dev/null 2>&1; then
    command -v "$1"
    return
  fi
  local candidate
  candidate="$(go env GOPATH)/bin/$1"
  if [ -x "$candidate" ]; then
    echo "$candidate"
  fi
}

# flag_set 从文件（或 - 表示的标准输入）里提取选项，归一化后排序去重。
# 归一化是因为 Go 的 flag 包把 -x 与 --x 当同一个：只比字面量会把
# README 的 -check 与 usage 的 --check 误判成两个不同的选项。
flag_set() {
  grep -oE -- '(^|[^[:alnum:]-])--?[a-z][a-z0-9-]*' "$@" |
    grep -oE -- '--?[a-z][a-z0-9-]*' | sed -E 's/^--/-/' | sort -u
}

# scan_terms 打印命中模式的文件行。扫描范围是本仓库自己的源文件与文档：dist/、
# 本地审查报告与使用者的真实配置都不在内。
scan_terms() {
  grep -rnE "$1" --include='*.go' --include='*.md' --include='*.yaml' . |
    grep -vE '^\./(dist/|REVIEW\.md:|config\.yaml:|[^/]*\.local\.yaml:)'
}

# terminology_check 挡住回潮的旧叫法，管两件事：
#  ① WireGuard 两侧是 peer，只有部署上不对称，所以叫承载层与对端。"服务端"
#     "客户端"在本仓库另有真正的主人——校园网服务端与命令行客户端——混着用会
#     把承载层公钥说成服务端公钥（它是本机生成的）。校园网那边的"服务端公钥"
#     （门户登录用的那把）不能被扫进来，所以模式带 WireGuard 前缀。
#  ② 指本机那个进程时一律写全"服务进程"：裸"服务"会跟校园网那边的服务端混。
terminology_check() {
  local hits
  hits=$(scan_terms 'WireGuard 服务端公钥|客户端公钥|服务端与客户端')
  if [ -n "$hits" ]; then
    echo "术语检查：WireGuard 两侧叫承载层与对端，命中旧叫法："
    echo "$hits"
    return 1
  fi
  hits=$(scan_terms '服务日志|服务是否在运行|查看服务与隧道状态')
  if [ -n "$hits" ]; then
    echo '术语检查：本机那个进程写"服务进程"，命中裸叫法：'
    echo "$hits"
    return 1
  fi
}
run terminology_check

# gofmt -l 有输出就算失败（它列出的是没格式化的文件）。
fmt_out=$(gofmt -l . 2>&1)
if [ -n "$fmt_out" ]; then
  echo "== gofmt -l ."
  echo "$fmt_out"
  fail=1
fi

run go vet ./...
run go build ./...
# 发布脚本给的六个组合都要能编译：Windows 与 macOS 的分支在 Linux 上编译不到，
# 交叉编译是它们唯一的守门人（曾经漏掉 windows/amd64 的一次改坏就是这么发现的）。
for target in linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64; do
  run env CGO_ENABLED=0 GOOS="${target%/*}" GOARCH="${target#*/}" go build ./...
done
run go test ./... -race
# 依赖面不许悄悄回涨：tidy 之后应当没有任何差异（悬空依赖、漏写的 require）。
run go mod tidy -diff

# 文档里的示例命令要真的存在。跑一遍示例要连服务端，离线能验的是这一半：
# README 提到的每个子命令都必须出现在 usage 里（原则 10：文档里写着而代码里
# 没有的东西是一个会误导人的缺陷）。选项同样双向对齐——曾经漏写过 start 的
# --trust：只查子命令时它照样全绿，用户看到 README 却不知道有这个开关。
doc_check() {
  local tmp bin helps missing
  tmp=$(mktemp -d)
  bin="$tmp/njuvpn"
  helps="$tmp/help.txt"
  if ! go build -o "$bin" ./cmd/njuvpn; then
    echo "文档命令检查：构建失败"
    rm -rf "$tmp"
    return 1
  fi
  "$bin" --help >"$helps" 2>&1
  local rc=0 cmd
  for cmd in $(grep -oE 'njuvpn [a-z]+' README.md | awk '{print $2}' | sort -u); do
    if ! grep -qE "^  njuvpn $cmd( |$)" "$helps" && ! grep -qE "^  \${?[a-z]*}?njuvpn $cmd( |$)" "$helps"; then
      echo "README 提到了子命令 $cmd，但 usage 里没有它"
      rc=1
    fi
  done
  flag_set README.md >"$tmp/readme.flags"
  flag_set "$helps" >"$tmp/help.flags"
  # README 里只有以 njuvpn 开头的行才算命令行：正文里写别的工具的选项
  # （比如 go build -o njuvpn）不该被要求出现在 usage 里。
  grep -E '^[[:space:]]*njuvpn ' README.md | flag_set - >"$tmp/readme.cmd.flags"
  missing=$(comm -23 "$tmp/help.flags" "$tmp/readme.flags")
  if [ -n "$missing" ]; then
    echo "usage 里的选项没有写进 README：$(echo "$missing" | paste -sd' ' -)"
    rc=1
  fi
  missing=$(comm -23 "$tmp/readme.cmd.flags" "$tmp/help.flags")
  if [ -n "$missing" ]; then
    echo "README 提到了 usage 里没有的选项：$(echo "$missing" | paste -sd' ' -)"
    rc=1
  fi
  rm -rf "$tmp"
  return $rc
}
run doc_check

sc=$(tool staticcheck)
if [ -n "$sc" ]; then
  run "$sc" ./...
else
  echo "== staticcheck 未安装，跳过（go install honnef.co/go/tools/cmd/staticcheck@2026.2.1）"
fi

dc=$(tool deadcode)
if [ -n "$dc" ]; then
  # -test 让测试引用的符号也算可达：测试替身不该被当成死代码。
  run "$dc" -test ./...
else
  echo "== deadcode 未安装，跳过（go install golang.org/x/tools/cmd/deadcode@latest）"
fi

if [ "$fail" -ne 0 ]; then
  echo
  echo "检查未通过"
  exit 1
fi
echo
echo "全部通过"
