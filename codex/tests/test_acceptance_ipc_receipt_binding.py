from __future__ import annotations

import json
import os
import socket
import stat
import struct
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import acceptance_broker_ipc as ipc
import acceptance_cli


@unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "pidfd_open"),
                     "Linux PIDFD required")
class BoundBrokerReceiptTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="orchestra-ipc-receipt-")
        self.addCleanup(temp.cleanup)
        self.ledger = Path(temp.name) / "ledger"
        self.ledger.mkdir(mode=0o700)
        (self.ledger / "used-nonces").touch(mode=0o600)
        self.key = Ed25519PrivateKey.generate()
        self.evaluator = {
            "evaluator_pid": os.getpid() + 8000,
            "evaluator_uid": os.getuid() + 2001,
            "evaluator_executable": [31, 47, stat.S_IFREG | 0o755, 0],
        }
        self.sent = []
        self.replies = []

    def _exchange(self, *, nonce="a" * 64, transform=None, raw=None,
                  peer_uid=0, expire=False, peer_exit_after=None):
        test = self

        class Broker:
            def __init__(self):
                self.buffer = None
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def settimeout(self, *_): pass
            def connect(self, *_): pass
            def getsockopt(self, _level, option, _size):
                if option == ipc.SO_PEERPIDFD:
                    return struct.pack("i", os.pidfd_open(os.getpid(), 0))
                return struct.pack("3i", os.getpid(), peer_uid, peer_uid)
            def sendall(self, payload):
                request = json.loads(payload)
                test.sent.append(request)
                body = {**request, **test.evaluator}
                if transform:
                    body = transform(body)
                signed = {**body, "signature": test.key.sign(
                    json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hex()}
                encoded = (json.dumps(signed, sort_keys=True) + "\n").encode()
                test.replies.append(encoded)
                self.buffer = encoded if raw is None else raw
            def recv(self, _size):
                if expire:
                    time.sleep(0.02)
                answer, self.buffer = self.buffer, b""
                return answer

        current = {"calls": 0}
        def peer_exited(_fd):
            current["calls"] += 1
            return peer_exit_after is not None and current["calls"] >= peer_exit_after

        with patch.object(ipc, "_trusted_endpoint", return_value=None), \
             patch.object(ipc, "_endpoint_identity", return_value=(2, 3), create=True), \
             patch.object(ipc.socket, "socket", return_value=Broker()), \
             patch.object(ipc, "_peer_exited", side_effect=peer_exited), \
             patch.object(ipc.secrets, "token_hex", return_value=nonce), \
             patch("acceptance_receipt.observe_evaluator",
                   return_value={"pid": self.evaluator["evaluator_pid"],
                                 "uid": self.evaluator["evaluator_uid"],
                                 "euid": self.evaluator["evaluator_uid"],
                                 "executable": self.evaluator["evaluator_executable"]}):
            return ipc._protected_receipt_at(
                ipc.BROKER_SOCKET, task_id="task-A", context_id="context-A",
                generation="generation-A", broker_verify_key=self.key.public_key(),
                ledger_dir=self.ledger)

    def test_live_signed_reply_is_consumed_but_not_installed_acceptance(self):
        result = self._exchange()
        self.assertEqual(result["status"], "verified_uninstalled", result)
        self.assertEqual(self.sent[0]["protocol"], 3)
        self.assertEqual(self.sent[0]["operation"], "protected-admission")
        self.assertEqual(len(self.sent[0]["nonce"]), 64)
        self.assertEqual((self.ledger / "used-nonces").read_text(), "a" * 64 + "\n")

    def test_signed_cross_action_and_stale_generation_context_nonce_are_rejected(self):
        mutations = (
            ("task_id", "task-B"), ("context_id", "context-B"),
            ("generation", "generation-B"), ("nonce", "b" * 64),
            ("operation", "probe"), ("verifier_pid", os.getpid() + 1),
        )
        for field, other in mutations:
            with self.subTest(field=field):
                result = self._exchange(transform=lambda data, f=field, v=other:
                                        {**data, f: v})
                self.assertEqual(result["status"], "blocked", result)
                self.assertEqual((self.ledger / "used-nonces").read_text(), "")

    def test_signed_wrong_verifier_executable_cannot_cross_into_action(self):
        result = self._exchange(transform=lambda data: {
            **data, "verifier_executable": [1, 2, 3, 4]})
        self.assertEqual(result["status"], "blocked", result)

    def test_signed_wrong_evaluator_kernel_identity_cannot_cross_into_action(self):
        result = self._exchange(transform=lambda data: {
            **data, "evaluator_uid": self.evaluator["evaluator_uid"] + 1})
        self.assertEqual(result["status"], "blocked", result)

    def test_delayed_signed_broker_reply_is_rejected_before_nonce_use(self):
        with patch.object(ipc, "CHALLENGE_TTL_NS", 1_000_000, create=True):
            result = self._exchange(expire=True)
        self.assertEqual(result["status"], "blocked", result)
        self.assertEqual((self.ledger / "used-nonces").read_text(), "")

    def test_broker_process_exit_during_reply_blocks(self):
        result = self._exchange(peer_exit_after=2)
        self.assertEqual(result["status"], "blocked", result)

    def test_reconnected_old_signed_reply_cannot_authorize_new_request(self):
        self.assertEqual(self._exchange(nonce="a" * 64)["status"], "verified_uninstalled")
        prior = self.replies[-1]
        result = self._exchange(nonce="b" * 64, raw=prior)
        self.assertEqual(result["status"], "blocked", result)
        self.assertEqual((self.ledger / "used-nonces").read_text(), "a" * 64 + "\n")

    def test_repeated_or_reattached_response_on_same_connection_is_rejected(self):
        result = self._exchange(raw=b'{"protocol":3}\n{"protocol":3}\n')
        self.assertEqual(result["status"], "blocked", result)

    def test_unprivileged_broker_cannot_advertise_root_ownership(self):
        result = self._exchange(peer_uid=os.getuid() + 1)
        self.assertEqual(result["status"], "blocked", result)
        self.assertEqual(self.sent, [])

    def test_real_unprivileged_socket_cannot_be_a_protected_broker(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broker.sock"
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(str(path))
                listener.listen(1)
                result = ipc._protected_receipt_at(
                    path, task_id="task-A", context_id="context-A",
                    generation="generation-A", broker_verify_key=self.key.public_key(),
                    ledger_dir=self.ledger)
        self.assertEqual(result["status"], "blocked", result)


if __name__ == "__main__":
    unittest.main()
