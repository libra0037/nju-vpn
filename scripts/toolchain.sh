#!/usr/bin/env bash
# Go 版本只取 go.mod；工具版本、构建标签与发布目标由这里统一维护。
GO_VERSION=$(awk '$1 == "go" {print $2}' go.mod)
STATICCHECK_VERSION=2026.2.1
DEADCODE_VERSION=v0.50.0
BUILD_TAGS=''
# 原生 runner 名称：https://docs.github.com/en/actions/reference/runners/github-hosted-runners
PLATFORMS=(
  linux/amd64:ubuntu-24.04
  linux/arm64:ubuntu-24.04-arm
  windows/amd64:windows-2025
  windows/arm64:windows-11-arm
  darwin/amd64:macos-15-intel
  darwin/arm64:macos-15
)

if [[ "${1:-}" == --matrix ]]; then
  printf '{"include":['
  separator=''
  for entry in "${PLATFORMS[@]}"; do
    target=${entry%:*}
    printf '%s{"target":"%s","runner":"%s"}' "$separator" "$target" "${entry#*:}"
    separator=,
  done
  printf ']}\n'
fi
