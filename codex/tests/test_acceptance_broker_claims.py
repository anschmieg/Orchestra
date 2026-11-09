from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import socket
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

from acceptance_broker_ipc import BROKER_SOCKET, REQUIRED_CAPABILITIES, SO_PEERPIDFD, _probe_at
from acceptance_cli import cmd_broker_status


@unittest.skipUnless(sys.platform.startswith('linux') and hasattr(os, 'pidfd_open'),
                     'requires a real Linux pidfd')
class UnverifiedContainmentClaimTests(unittest.TestCase):
    def _connected_transport_only(self):
        class Peer:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def settimeout(self, *_): pass
            def connect(self, *_): pass
            def getsockopt(self, level, option, length):
                if option == SO_PEERPIDFD:
                    return struct.pack('i', os.pidfd_open(os.getpid(), 0))
                return struct.pack('3i', os.getpid(), 0, 0)
            def sendall(self, data):
                self.nonce = json.loads(data)['nonce']
            def recv(self, _):
                return (json.dumps({
                    'protocol': 1, 'operation': 'probe', 'nonce': self.nonce,
                    'status': 'ready', 'capabilities': sorted(REQUIRED_CAPABILITIES),
                }) + '\n').encode()
        with patch('acceptance_broker_ipc._trusted_endpoint', return_value=None), \
             patch('acceptance_broker_ipc.socket.socket', return_value=Peer()):
            return _probe_at(BROKER_SOCKET)

    def _assert_no_success(self, result):
        self.assertEqual(result['status'], 'connected_unverified')
        output = io.StringIO()
        with patch('acceptance_cli.probe_broker', return_value=result), \
             contextlib.redirect_stdout(output):
            code = cmd_broker_status(argparse.Namespace())
        self.assertEqual(json.loads(output.getvalue())['status'], 'connected_unverified')
        self.assertEqual(code, 1, 'unverified containment must not produce CLI success')

    def test_wrong_cgroup_ownership_cannot_be_authenticated_by_capabilities(self):
        if os.geteuid() == 0:
            self.skipTest('requires a non-root cgroup surrogate owner')
        with tempfile.TemporaryDirectory(prefix='orchestra-untrusted-cgroup-') as directory:
            self.assertEqual(Path(directory).stat().st_uid, os.geteuid())
            self.assertNotEqual(Path(directory).stat().st_uid, 0)
            self._assert_no_success(self._connected_transport_only())

    def test_escaped_descendants_cannot_be_authenticated_by_capabilities(self):
        self._assert_no_success(self._connected_transport_only())

    def test_stale_containment_generation_cannot_be_authenticated_by_nonce(self):
        first = self._connected_transport_only()
        second = self._connected_transport_only()
        self._assert_no_success(first)
        self._assert_no_success(second)


if __name__ == '__main__':
    unittest.main()
