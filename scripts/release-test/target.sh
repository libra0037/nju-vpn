#!/usr/bin/env bash
# 仅由实机脚本入口读取部署目标，不把地址写进源码或公开摘要。
test_target=$(python3 "$(dirname "${BASH_SOURCE[0]}")/target_ip.py")
