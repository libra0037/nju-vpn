import os
import unittest
from unittest.mock import patch

from target_ip import parse_target_ip, target_from_environment


class TargetBoundaryTests(unittest.TestCase):
    def test_reject_invalid_without_echoing_input(self):
        for value in ('', '::1', '127.0.0.1', '0.0.0.0', '224.0.0.1',
                      '255.255.255.255', '192.0.2.1:80', '192.0.2.1/32',
                      'marker-secret-host'):
            with self.subTest(kind=value[:1]):
                with self.assertRaises(ValueError) as caught:
                    parse_target_ip(value)
                self.assertNotIn('marker-secret-host', str(caught.exception))

    def test_valid_and_explicit_environment(self):
        for value in ('192.0.2.1', '10.0.0.1'):
            self.assertEqual(parse_target_ip(value), value)
        with patch.dict(os.environ, {'NJUVPN_TEST_TARGET_IP': '198.51.100.1'}):
            self.assertEqual(target_from_environment(), '198.51.100.1')


if __name__ == '__main__':
    unittest.main()
