"""实机目标由环境显式提供；文档与离线用例使用保留地址。"""
import ipaddress
import os
import sys


def parse_target_ip(value):
    try:
        if not value or len(value) > 15:
            raise ValueError
        address = ipaddress.IPv4Address(value)
        if address.is_loopback or address.is_unspecified or address.packed[0] >= 224:
            raise ValueError
        return str(address)
    except ValueError:
        raise ValueError('需设置 NJUVPN_TEST_TARGET_IP 为有效的非回环 IPv4 地址') from None


def target_from_environment():
    return parse_target_ip(os.environ.get('NJUVPN_TEST_TARGET_IP', ''))


if __name__ == '__main__':
    try:
        print(target_from_environment())
    except ValueError as error:
        sys.exit(str(error))
