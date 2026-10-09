#!/usr/bin/env python3
"""临时受控测试目标：固定载荷、有限请求、无文件访问、无访客地址日志。"""
import argparse
import ipaddress
import http.server
import hashlib
import json
import re
import signal
import socket
import socketserver
import threading
import time

PAYLOAD = bytes(range(256)) * 32768
HEALTH_BODY = b'njuvpn-release-test\n'
# 2 Mbit/s 传 8 MiB 正文需 33.6 秒；总期限留余量，停滞期限单独保留。
REQUEST_TIMEOUT = 60
IDLE_TIMEOUT = 20
MAX_HTTP_TRACES = 64
TCP_FIXTURE = bytes(range(256)) * 4096
TCP_FIXTURE_HASH = 'fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83'


class TCPServer(socketserver.ThreadingTCPServer):
    """18082 等上传 EOF 后回应，18083 回显供端点交错测试持有连接。"""
    allow_reuse_address = True
    daemon_threads = False

    def __init__(self, address, half_close, timeout=120):
        self.half_close = half_close
        self.request_timeout = timeout
        self.slots = threading.BoundedSemaphore(8)
        self.lock = threading.Lock()
        self.connections = set()
        self.closing = False
        self.trace_count = 0
        # TCPServer 绑定失败时也会调用 server_close，状态必须先成立。
        super().__init__(address, TCPHandler)

    def process_request(self, request, address):
        with self.lock:
            if self.closing or not self.slots.acquire(blocking=False):
                request.close()
                return
            self.connections.add(request)
            # 注册工作者须与关闭快照串行；这里只启动线程，不做网络读写。
            try:
                super().process_request(request, address)
            except BaseException:
                self.connections.discard(request)
                self.slots.release()
                request.close()
                raise

    def process_request_thread(self, request, address):
        def deadline():
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        timer = threading.Timer(self.request_timeout, deadline)
        timer.start()
        try:
            request.settimeout(self.request_timeout)
            super().process_request_thread(request, address)
        finally:
            timer.cancel()
            timer.join()
            with self.lock:
                self.connections.discard(request)
            self.slots.release()

    def server_close(self):
        # 先阻止接收并关闭现有连接，再由 ThreadingMixIn 等待工作者。
        with self.lock:
            self.closing = True
            connections = list(self.connections)
        for request in connections:
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        super().server_close()

    def handle_error(self, request, address):
        pass

    def record(self, record):
        with self.lock:
            if self.trace_count < 32:
                self.trace_count += 1
                print('TCP ' + json.dumps(record, separators=(',', ':')), flush=True)


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        started = time.monotonic()
        count = 0
        digest = hashlib.sha256()
        error = None
        try:
            limit = len(TCP_FIXTURE) if self.server.half_close else 2 * len(TCP_FIXTURE)
            while True:
                body = self.request.recv(min(65536, limit - count + 1))
                if not body:
                    break
                count += len(body)
                if count > limit:
                    raise ValueError('输入超过固定上限')
                digest.update(body)
                if not self.server.half_close:
                    self.request.sendall(body)
            if self.server.half_close:
                if count != len(TCP_FIXTURE) or digest.hexdigest() != TCP_FIXTURE_HASH:
                    raise ValueError('固定上传内容错误')
                self.request.sendall(TCP_FIXTURE)
                self.request.shutdown(socket.SHUT_WR)
        except (OSError, ValueError) as exc:
            error = type(exc).__name__
        finally:
            self.server.record(dict(kind='half_close' if self.server.half_close else 'echo',
                                    input_bytes=count, sha256=digest.hexdigest(), error_type=error,
                                    elapsed_ms=round((time.monotonic() - started) * 1000)))


class Server(http.server.ThreadingHTTPServer):
    # 关闭时等待工作者；每个工作者都受请求期限约束并回收自己的计时器。
    daemon_threads = False

    def __init__(self, address, timeout=REQUEST_TIMEOUT, idle_timeout=IDLE_TIMEOUT):
        super().__init__(address, Handler)
        self.request_timeout = timeout
        self.idle_timeout = idle_timeout
        self.slots = threading.BoundedSemaphore(8)
        self.trace_lock = threading.Lock()
        self.trace_count = 0

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        started = time.monotonic()
        deadline_fired = threading.Event()
        # 只有当前工作者更新这份记录；计时器仅设置 Event 并关闭连接。
        trace = dict(kind='other', run_id=None, status=None, request_bytes=None,
                     response_bytes=0, expected_bytes=None, complete=False,
                     error_type=None, headers_ms=None, request_expected_bytes=None,
                     request_first_byte_ms=None, request_last_byte_ms=None,
                     expect_continue=None)

        def deadline():
            deadline_fired.set()
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            request.close()
        timer = threading.Timer(self.request_timeout, deadline)
        timer.start()
        try:
            Handler(request, address, self, trace=trace, started=started)
        except Exception as error:
            trace['error_type'] = type(error).__name__
        finally:
            timer.cancel()
            timer.join()
            self.shutdown_request(request)
            trace.update(elapsed_ms=round((time.monotonic() - started) * 1000),
                         deadline_ms=round(self.request_timeout * 1000),
                         idle_timeout_ms=round(self.idle_timeout * 1000),
                         deadline_fired=deadline_fired.is_set())
            self.record_trace(trace)
            self.slots.release()

    def record_trace(self, trace):
        # 固定字段、最多 64 条记录；串行打印避免工作者把同一行写碎。
        with self.trace_lock:
            if self.trace_count < MAX_HTTP_TRACES:
                self.trace_count += 1
                print('HTTP ' + json.dumps(trace, separators=(',', ':')), flush=True)

    def handle_error(self, request, address):
        pass


class Handler(http.server.BaseHTTPRequestHandler):
    def __init__(self, *args, trace, started):
        self.trace = trace
        self.started = started
        super().__init__(*args)

    def setup(self):
        super().setup()
        self.connection.settimeout(self.server.idle_timeout)

    def log_message(self, *args):
        pass

    def log_error(self, message, *args):
        # 标准处理器会捕获 socket 超时；保留类型，不输出可能含地址的错误正文。
        for value in args:
            if isinstance(value, Exception):
                self.trace['error_type'] = type(value).__name__

    def send_response(self, code, message=None):
        self.trace['status'] = code
        super().send_response(code, message)

    def identify(self, kind):
        self.trace['kind'] = kind
        self.trace['headers_ms'] = round((time.monotonic() - self.started) * 1000)
        value = self.headers.get('X-Njuvpn-Test-Id', '')
        # 只接受测试工具生成的随机标识，绝不记录其他头、原始路径或地址。
        if re.fullmatch('[0-9a-f]{32}', value):
            self.trace['run_id'] = value

    def reply(self, body, slow=False):
        self.trace['expected_bytes'] = len(body)
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        for position in range(0, len(body), 65536):
            part = body[position:position+65536]
            self.wfile.write(part)
            self.trace['response_bytes'] += len(part)
            if slow:
                time.sleep(0.01)
        self.trace['complete'] = True

    def do_GET(self):
        if self.path == '/health':
            self.identify('health')
            self.reply(HEALTH_BODY)
        elif self.path in ('/blob', '/slow-blob'):
            self.identify('slow_download' if self.path == '/slow-blob' else 'download')
            self.reply(PAYLOAD, self.path == '/slow-blob')
        else:
            self.send_error(404)

    def do_HEAD(self):
        # mihomo 的节点健康检查使用 HEAD；正文长度与 GET 相同但不发送正文。
        if self.path != '/health':
            self.send_error(404)
            return
        self.identify('health_head')
        self.trace['expected_bytes'] = 0
        self.send_response(200)
        self.send_header('Content-Length', str(len(HEALTH_BODY)))
        self.end_headers()
        self.trace['complete'] = True

    def do_POST(self):
        self.identify('upload' if self.path == '/echo' else 'other')
        try:
            size = int(self.headers.get('Content-Length', '-1'))
        except ValueError:
            size = -1
        if self.path != '/echo' or not 0 <= size <= 1024 * 1024:
            self.send_error(400)
            return
        self.trace['request_expected_bytes'] = size
        self.trace['expect_continue'] = self.headers.get('Expect', '').lower() == '100-continue'
        self.trace['request_bytes'] = 0
        body = bytearray()
        # 一次 read(size) 超时会丢失部分读取的计数；逐次记录已有进展。
        # read1 每次最多一次底层读取，正文始终受上面的 1 MiB 上限约束。
        while len(body) < size:
            part = self.rfile.read1(min(65536, size - len(body)))
            if not part:
                break
            body.extend(part)
            elapsed = round((time.monotonic() - self.started) * 1000)
            if self.trace['request_first_byte_ms'] is None:
                self.trace['request_first_byte_ms'] = elapsed
            self.trace['request_last_byte_ms'] = elapsed
            self.trace['request_bytes'] = len(body)
        if len(body) != size:
            self.send_error(400)
            return
        self.reply(body)


def echo_udp(udp, closed):
    reported = 0
    while not closed.is_set():
        try:
            body, peer = udp.recvfrom(4097)
            if len(body) <= 4096:
                if reported < 16:
                    print('UDP 收到载荷字节数：' + str(len(body)), flush=True)
                    reported += 1
                # 大请求用小摘要确认重组内容，避免同时依赖目标端的下行分片。
                reply = hashlib.sha256(body).digest() if body.startswith(b'NJUVPN-SHA256:') else body
                udp.sendto(reply, peer)
        except socket.timeout:
            continue
        except OSError:
            break


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--bind', default='127.0.0.1')
    args = parser.parse_args()
    try:
        bind = str(ipaddress.IPv4Address(args.bind))
    except ValueError:
        raise SystemExit('绑定参数必须为 IPv4 地址') from None
    closed = threading.Event()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tcp_servers = []
    try:
        udp.bind((bind, 18081))
        udp.settimeout(0.5)
        server = Server((bind, 18080))
        tcp_servers.append(TCPServer((bind, 18082), half_close=True))
        tcp_servers.append(TCPServer((bind, 18083), half_close=False))
    except BaseException:
        udp.close()
        for tcp in tcp_servers:
            tcp.server_close()
        if 'server' in locals():
            server.server_close()
        raise
    thread = threading.Thread(target=echo_udp, args=(udp, closed))
    thread.start()
    tcp_threads = [threading.Thread(target=tcp.serve_forever) for tcp in tcp_servers]
    for worker in tcp_threads:
        worker.start()
    signal.signal(signal.SIGTERM, lambda *args: closed.set())
    signal.signal(signal.SIGINT, lambda *args: closed.set())
    server.timeout = 0.5
    print('测试目标已启动：HTTP 18080、UDP 18081、TCP 18082/18083', flush=True)
    try:
        while not closed.is_set():
            server.handle_request()
    finally:
        closed.set()
        server.server_close()
        udp.close()
        thread.join()
        for tcp in tcp_servers:
            tcp.shutdown()
            tcp.server_close()
        for worker in tcp_threads:
            worker.join()


if __name__ == '__main__':
    main()
