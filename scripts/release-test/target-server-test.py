#!/usr/bin/env python3
"""检查受控目标的真实请求期限、关闭等待和脱敏记录。"""
import contextlib
import http.client
import importlib.util
import io
import json
import pathlib
import socket
import threading
import time
import unittest

spec = importlib.util.spec_from_file_location(
    'target_server', pathlib.Path(__file__).with_name('target-server.py'))
target = importlib.util.module_from_spec(spec)
spec.loader.exec_module(target)


class ObservedServer(target.Server):
    def __init__(self, timeout, idle_timeout):
        super().__init__(('127.0.0.1', 0), timeout, idle_timeout)
        self.recorded = threading.Event()
        self.records = []

    def record_trace(self, trace):
        super().record_trace(trace)
        self.records.append(trace)
        self.recorded.set()


class TargetTest(unittest.TestCase):
    def start_server(self, timeout, idle_timeout=2):
        server = ObservedServer(timeout, idle_timeout)
        thread = threading.Thread(target=server.serve_forever,
                                  kwargs={'poll_interval': 0.01})
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def test_request_records_only_valid_identifier_and_counts(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            server = self.start_server(1)
            client = http.client.HTTPConnection(*server.server_address, timeout=2)
            try:
                run_id = '0123456789abcdef0123456789abcdef'
                client.request('GET', '/health', headers={'X-Njuvpn-Test-Id': run_id,
                                                         'Authorization': 'secret-token'})
                response = client.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(response.read(), b'njuvpn-release-test\n')
                self.assertTrue(server.recorded.wait(1))
            finally:
                client.close()
        record = json.loads(output.getvalue().removeprefix('HTTP '))
        self.assertEqual(record['run_id'], run_id)
        self.assertEqual(record['response_bytes'], 20)
        self.assertTrue(record['complete'])
        self.assertFalse(record['deadline_fired'])
        self.assertNotIn('secret-token', output.getvalue())
        self.assertNotIn('127.0.0.1', output.getvalue())
        self.assertNotIn('/health', output.getvalue())

    def test_head_health_has_get_length_without_body(self):
        with contextlib.redirect_stdout(io.StringIO()):
            server = self.start_server(1)
            client = http.client.HTTPConnection(*server.server_address, timeout=2)
            try:
                client.request('HEAD', '/health')
                response = client.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(response.getheader('Content-Length'), '20')
                self.assertEqual(response.read(), b'')
                self.assertTrue(server.recorded.wait(1))
            finally:
                client.close()
        self.assertEqual(server.records[0]['kind'], 'health_head')
        self.assertEqual(server.records[0]['response_bytes'], 0)
        self.assertTrue(server.records[0]['complete'])

    def test_progressing_upload_can_outlive_idle_timeout(self):
        with contextlib.redirect_stdout(io.StringIO()):
            server = self.start_server(3, idle_timeout=0.5)
            client = socket.create_connection(server.server_address, timeout=3)
            try:
                client.sendall(b'POST /echo HTTP/1.0\r\nContent-Length: 10\r\n\r\n')
                # 总耗时超过停滞期限，但每次读取都有进展；两个期限必须独立。
                for _ in range(10):
                    client.sendall(b'x')
                    time.sleep(0.1)
                response = http.client.HTTPResponse(client)
                response.begin()
                self.assertEqual(response.status, 200)
                self.assertEqual(response.read(), b'x' * 10)
                self.assertTrue(server.recorded.wait(1))
            finally:
                client.close()
        self.assertTrue(server.records[0]['complete'])
        self.assertFalse(server.records[0]['deadline_fired'])
        self.assertEqual(server.records[0]['request_bytes'], 10)
        self.assertEqual(server.records[0]['request_expected_bytes'], 10)
        self.assertLessEqual(server.records[0]['headers_ms'],
                             server.records[0]['request_first_byte_ms'])
        self.assertLess(server.records[0]['request_first_byte_ms'],
                        server.records[0]['request_last_byte_ms'])

    def test_idle_upload_is_closed_before_overall_deadline(self):
        with contextlib.redirect_stdout(io.StringIO()):
            server = self.start_server(2, idle_timeout=0.2)
            client = socket.create_connection(server.server_address, timeout=2)
            try:
                client.sendall(b'POST /echo HTTP/1.0\r\nContent-Length: 10\r\n\r\n')
                self.assertTrue(server.recorded.wait(1))
                self.assertEqual(client.recv(1024), b'')
            finally:
                client.close()
        self.assertFalse(server.records[0]['complete'])
        self.assertFalse(server.records[0]['deadline_fired'])
        self.assertEqual(server.records[0]['error_type'], 'TimeoutError')
        self.assertEqual(server.records[0]['request_bytes'], 0)
        self.assertIsNone(server.records[0]['request_first_byte_ms'])

    def test_partial_upload_retains_progress_after_idle_timeout(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            server = self.start_server(2, idle_timeout=0.2)
            client = socket.create_connection(server.server_address, timeout=2)
            try:
                client.sendall(b'POST /echo HTTP/1.1\r\nContent-Length: 10\r\n'
                               b'Expect: 100-continue\r\nAuthorization: secret-token\r\n\r\n'
                               b'abc')
                self.assertTrue(server.recorded.wait(1))
                self.assertEqual(client.recv(1024), b'')
            finally:
                client.close()
        record = server.records[0]
        self.assertEqual(record['request_bytes'], 3)
        self.assertEqual(record['request_expected_bytes'], 10)
        self.assertTrue(record['expect_continue'])
        self.assertIsNotNone(record['request_last_byte_ms'])
        self.assertLess(record['request_last_byte_ms'], record['elapsed_ms'])
        self.assertEqual(record['error_type'], 'TimeoutError')
        self.assertFalse(record['deadline_fired'])
        self.assertFalse(record['complete'])
        self.assertNotIn('secret-token', output.getvalue())
        self.assertNotIn('abc', output.getvalue())

    def test_partial_upload_eof_is_counted_and_rejected(self):
        with contextlib.redirect_stdout(io.StringIO()):
            server = self.start_server(2)
            client = socket.create_connection(server.server_address, timeout=2)
            try:
                client.sendall(b'POST /echo HTTP/1.0\r\nContent-Length: 10\r\n\r\nabc')
                client.shutdown(socket.SHUT_WR)
                response = http.client.HTTPResponse(client)
                response.begin()
                self.assertEqual(response.status, 400)
                response.read()
                self.assertTrue(server.recorded.wait(1))
            finally:
                client.close()
        self.assertEqual(server.records[0]['request_bytes'], 3)
        self.assertFalse(server.records[0]['complete'])
        self.assertFalse(server.records[0]['deadline_fired'])

    def test_stalled_upload_is_closed_by_owned_deadline(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            server = self.start_server(0.2)
            client = socket.create_connection(server.server_address, timeout=2)
            try:
                client.sendall(b'POST /echo HTTP/1.0\r\nContent-Length: 1048576\r\n'
                               b'X-Njuvpn-Test-Id: secret-token-address\r\n\r\n')
                self.assertTrue(server.recorded.wait(2))
                self.assertEqual(client.recv(1024), b'')
            finally:
                client.close()
        record = json.loads(output.getvalue().removeprefix('HTTP '))
        self.assertTrue(record['deadline_fired'])
        self.assertFalse(record['complete'])
        self.assertEqual(record['kind'], 'upload')
        self.assertIsNone(record['run_id'])
        self.assertLess(record['elapsed_ms'], 1500)
        self.assertNotIn('secret-token-address', output.getvalue())


if __name__ == '__main__':
    unittest.main()
