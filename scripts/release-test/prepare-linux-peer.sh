#!/usr/bin/env bash
# 在普通账户下准备测试对端；只修改用户指定的独立测试配置。
set -euo pipefail
source "$(dirname "$0")/target.sh"
cd "$(dirname "$0")"
config=${1:?用法: bash prepare-linux-peer.sh /绝对路径/测试配置.yaml}
config=$(realpath "$config")
umask 077
private=$(mktemp -d "$(dirname "$config")/private-peer-XXXXXX")
state=$(./test-helper state -config "$config" 2>/dev/null || true)
if [[ -n $state && $state != idle ]]; then
  echo '测试实例已有活动会话，请先停止再准备对端' >&2
  exit 1
fi
./njuvpn restart -config "$config" > "$private/restart.log" 2>&1
./test-helper new-peer -out "$private" > "$private/public.json"
python3 - "$config" "$private/public.json" <<'PY'
import json, os, pathlib, re, sys, tempfile
path = pathlib.Path(sys.argv[1])
public = json.loads(pathlib.Path(sys.argv[2]).read_text())['public_key']
body, count = re.subn(r'^  peer_public_key:.*$', '  peer_public_key: "' + public + '"', path.read_text(), flags=re.M)
if count != 1:
    raise SystemExit('配置必须保留样例中的唯一 peer_public_key 行，请手动填写公钥')
fd, temp = tempfile.mkstemp(dir=path.parent, prefix='.test-peer-')
try:
    with os.fdopen(fd, 'w') as file:
        file.write(body)
        file.flush()
        os.fsync(file.fileno())
    os.replace(temp, path)
finally:
    if os.path.exists(temp):
        os.unlink(temp)
PY
./njuvpn restart -config "$config" >> "$private/restart.log" 2>&1
./test-helper info -config "$config" > "$private/info.json"
python3 - "$private" <<'PY'
import json, os, pathlib, sys
directory = pathlib.Path(sys.argv[1])
info = json.loads((directory / 'info.json').read_text())
if not info['wireguard_enabled'] or info['mtu'] != 1400 or info['listen_host'] not in ('', 'loopback'):
    raise SystemExit('实机测试要求启用 WireGuard、MTU 1400、loopback 监听')
key = (directory / 'peer.key').read_text().strip()
body = '[Interface]\nPrivateKey = ' + key + '\n\n[Peer]\nPublicKey = ' + info['public_key'] + '\nEndpoint = 127.0.0.1:' + str(info['listen_port']) + '\nAllowedIPs = ' + os.environ['NJUVPN_TEST_TARGET_IP'] + '/32\nPersistentKeepalive = 25\n'
(directory / 'peer.conf').write_text(body)
PY
printf '对端已准备。请在服务器执行：\nsudo --preserve-env=NJUVPN_TEST_TARGET_IP bash %q %q\n' "$PWD/setup-linux-peer.sh" "$private"
