#!/usr/bin/env python3
"""受控目标的独立内容校验；不输出目标地址、响应正文或套接字错误详情。"""
import hashlib
import http.client
import json
import socket
import sys

from target_ip import target_from_environment

HTTP_PORT = 18080
UDP_PORT = 18081


def http_request(target, method, path, body=None):
    connection = http.client.HTTPConnection(target, HTTP_PORT, timeout=30)
    try:
        connection.request(method, path, body=body)
        response = connection.getresponse()
        data = response.read(8 * 1024 * 1024 + 1)
        if response.status != 200:
            raise RuntimeError('HTTP 状态码不正确')
        return data
    finally:
        connection.close()


def main():
    mode = None
    phase = 'arguments'
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in ('baseline', 'online', 'stopped'):
            raise RuntimeError('需要 baseline、online 或 stopped')
        target = target_from_environment()
        mode = sys.argv[1]
        phase = mode
        if mode != 'online':
            try:
                http_request(target, 'GET', '/health')
            except (OSError, http.client.HTTPException):
                print(json.dumps({'mode': mode, 'direct_unreachable': True}))
                return 0
            raise RuntimeError('测试目标仍可访问，不能证明流量依赖本次 VPN')
        phase = 'http-health'
        if http_request(target, 'GET', '/health') != b'njuvpn-release-test\n':
            raise RuntimeError('健康检查内容不一致')
        payload = bytes(range(256)) * 32768
        phase = 'http-download'
        downloaded = http_request(target, 'GET', '/blob')
        if downloaded != payload:
            raise RuntimeError('8 MiB 下载内容不一致')
        upload = payload[:1024 * 1024]
        phase = 'http-upload'
        echoed = http_request(target, 'POST', '/echo', upload)
        if echoed != upload:
            raise RuntimeError('1 MiB 上传回传内容不一致')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(30)
            udp.connect((target, UDP_PORT))
            for size in (32, 1372, 2000, 4000):
                phase = 'udp-' + str(size)
                message = bytes(index % 251 for index in range(size))
                if size > 1372:
                    prefix = b'NJUVPN-SHA256:'
                    message = prefix + message[len(prefix):]
                udp.send(message)
                received = udp.recv(4097)
                expected = hashlib.sha256(message).digest() if size > 1372 else message
                if received != expected:
                    raise RuntimeError('UDP 回传内容不一致')
    except Exception as error:
        print(json.dumps({'mode': mode, 'pass': False, 'phase': phase,
                          'error_type': type(error).__name__}))
        return 1
    print(json.dumps({'mode': mode, 'health': True, 'download_bytes': len(downloaded),
                      'upload_bytes': len(upload), 'download_sha256': hashlib.sha256(downloaded).hexdigest(),
                      'udp_payload_bytes': [32, 1372, 2000, 4000]}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
