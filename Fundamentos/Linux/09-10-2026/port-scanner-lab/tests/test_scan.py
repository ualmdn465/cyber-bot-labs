
import errno
import socket
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import scan


class FakeSocket:
    def __init__(self, outcome):
        self.outcome = outcome

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect_ex(self, address):
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


class TestPortScanner(unittest.TestCase):

    def test_parse_port_range(self):
        self.assertEqual(
            scan.parse_ports("8000-8002"),
            [8000, 8001, 8002],
        )

    def test_rejects_external_target_without_flag(self):
        with self.assertRaises(ValueError):
            scan.validate_target("192.0.2.1", False)

    @patch("scan.socket.socket", return_value=FakeSocket(0))
    def test_open_port(self, _mock_socket):
        result = scan.scan_port("127.0.0.1", 9000, 0.5)
        self.assertEqual(result["state"], "open")

    @patch(
        "scan.socket.socket",
        return_value=FakeSocket(errno.ECONNREFUSED),
    )
    def test_closed_port(self, _mock_socket):
        result = scan.scan_port("127.0.0.1", 9001, 0.5)
        self.assertEqual(result["state"], "closed")

    @patch(
        "scan.socket.socket",
        return_value=FakeSocket(socket.timeout("simulated timeout")),
    )
    def test_timeout_is_filtered(self, _mock_socket):
        result = scan.scan_port("127.0.0.1", 9002, 0.5)
        self.assertEqual(result["state"], "filtered")

    @patch("scan.socket.socket", return_value=FakeSocket(errno.EAGAIN))
    def test_timeout_code_is_filtered(self, _mock_socket):
        # Un timeout real con connect_ex devuelve EAGAIN en vez de lanzar excepción
        result = scan.scan_port("127.0.0.1", 9003, 0.5)
        self.assertEqual(result["state"], "filtered")


if __name__ == "__main__":
    unittest.main()
