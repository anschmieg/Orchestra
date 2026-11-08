from __future__ import annotations

import json
import os
import socket
import stat
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

from acceptance_broker_ipc import probe_broker, _probe_at


class BrokerIpcAdversarialTests(unittest.TestCase):
    def test_missing_broker_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            result = _probe_at(Path(directory) / 'missing.sock')
        self.assertEqual(result['status'], 'blocked')

    def test_unprivileged_socket_cannot_impersonate_root_broker(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'spoof.sock'
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(str(path))
                listener.listen(1)
                result = _probe_at(path)
            self.assertEqual(result['status'], 'blocked')

    def test_nonroot_peer_rejected_before_any_request(self):
        class Peer:
            def __init__(self):
                self.sent = b''
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def settimeout(self, *_):
                pass
            def connect(self, *_):
                pass
            def getsockopt(self, *_):
                return struct.pack('3i', 111, 1000, 1000)
            def sendall(self, data):
                self.sent += data
        fake = Peer()
        with patch('acceptance_broker_ipc._trusted_endpoint', return_value=None), patch('acceptance_broker_ipc.socket.socket', return_value=fake):
            result = _probe_at(Path('/run/orchestra-acceptance/broker.sock'))
        self.assertEqual(result['status'], 'blocked')
        self.assertEqual(fake.sent, b'')

    def test_truncated_response_after_broker_sigkill_blocks(self):
        result = self._simulate(b'{"protocol":1,"nonce":"test-nonce"')
        self.assertEqual(result['status'], 'blocked')

    def test_wrong_nonce_replay_blocks(self):
        result = self._simulate(self._reply(nonce='stale-nonce'))
        self.assertEqual(result['status'], 'blocked')

    def test_fake_acceptance_or_pid_reaping_is_not_containment(self):
        for status in ('accepted', 'pid-reaped', 'pass'):
            with self.subTest(status=status):
                result = self._simulate(self._reply(status=status))
                self.assertEqual(result['status'], 'blocked')

    def test_missing_double_fork_and_cgroup_capabilities_blocks(self):
        for capabilities in (
            ['separate-evaluator-uid'],
            ['separate-evaluator-uid', 'cgroup-v2'],
            ['separate-evaluator-uid', 'cgroup-v2', 'recursive-kill'],
        ):
            with self.subTest(capabilities=capabilities):
                result = self._simulate(self._reply(capabilities=capabilities))
                self.assertEqual(result['status'], 'blocked')

    def test_malformed_capabilities_fail_closed_without_exception(self):
        result = self._simulate(self._reply(capabilities=[["cgroup-v2"], "recursive-kill", "separate-evaluator-uid", "broker-sigkill-recovery"]))
        self.assertEqual(result["status"], "blocked")

    def test_valid_root_handshake_only_attests_transport_not_acceptance(self):
        result = self._simulate(self._reply())
        self.assertEqual(result['status'], 'connected_unverified')
        self.assertNotIn('accepted', result.values())

    def _reply(self, *, nonce='test-nonce', status='ready', capabilities=None):
        if capabilities is None:
            capabilities = ['separate-evaluator-uid', 'cgroup-v2', 'recursive-kill', 'broker-sigkill-recovery']
        return (json.dumps({
            'protocol': 1, 'operation': 'probe', 'nonce': nonce,
            'status': status, 'capabilities': capabilities,
        }).encode('utf-8') + b'\n')

    def _simulate(self, reply):
        class RootPeer:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def settimeout(self, *_):
                pass
            def connect(self, *_):
                pass
            def getsockopt(self, *_):
                return struct.pack('3i', 123, 0, 0)
            def sendall(self, message):
                request = json.loads(message)
                assert request == {'protocol': 1, 'operation': 'probe', 'nonce': 'test-nonce'}
            def recv(self, _):
                nonlocal reply
                result, reply = reply, b''
                return result
        with patch('acceptance_broker_ipc._trusted_endpoint', return_value=None), patch('acceptance_broker_ipc.socket.socket', return_value=RootPeer()), patch('acceptance_broker_ipc.secrets.token_hex', return_value='test-nonce'):
            return _probe_at(Path('/run/orchestra-acceptance/broker.sock'))


if __name__ == '__main__':
    unittest.main()
