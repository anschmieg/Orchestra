from __future__ import annotations

import json
import os
import signal
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from acceptance_receipt import _consume_once, _executable_identity, verify_one_use_receipt
import acceptance_cli


@unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "pidfd_open"), "Linux pidfd required")
class SignedAdmissionReceiptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="orchestra-one-use-receipt-")
        self.addCleanup(self.tmp.cleanup)
        self.ledger = Path(self.tmp.name) / "protected-ledger"
        self.ledger.mkdir(mode=0o700)
        (self.ledger / "used-nonces").touch(mode=0o600)
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key()
        now = time.monotonic_ns()
        self.challenge = {
            "nonce": "a" * 64,
            "task_id": "task-A",
            "context_id": "context-A",
            "generation": "cg-generation-A",
            "issued_monotonic_ns": now - 10_000_000,
            "expires_monotonic_ns": now + 4_000_000_000,
            "verifier_pid": os.getpid(),
            "verifier_uid": os.getuid(),
            "verifier_euid": os.geteuid(),
            "verifier_executable": _executable_identity("/proc/self/exe"),
        }
        self.evaluator = {
            "evaluator_pid": os.getpid() + 4000,
            "evaluator_uid": os.getuid() + 2000,
            "evaluator_executable": [18, 23, stat.S_IFREG | 0o755, 0],
        }

    def receipt(self, **changes):
        claim = {
            **self.challenge, **self.evaluator,
            "protocol": 3,
            "operation": "protected-admission",
        }
        claim.update(changes)
        signature = self.key.sign(json.dumps(claim, sort_keys=True, separators=(",", ":")).encode())
        return {**claim, "signature": signature.hex()}

    def observer(self, pid):
        self.assertEqual(pid, self.evaluator["evaluator_pid"])
        return {
            "pid": pid,
            "uid": self.evaluator["evaluator_uid"],
            "euid": self.evaluator["evaluator_uid"],
            "executable": self.evaluator["evaluator_executable"],
        }

    def verify(self, receipt, challenge=None, *, observer=None):
        with patch("acceptance_receipt.observe_evaluator", side_effect=observer or self.observer):
            return verify_one_use_receipt(
                receipt, self.challenge if challenge is None else challenge,
                self.public, self.ledger)

    def test_fresh_signed_receipt_is_verified_but_never_installation_acceptance(self):
        result = self.verify(self.receipt())
        self.assertEqual(result["status"], "verified_uninstalled", result)
        self.assertNotIn(result["status"], {"ok", "accepted", "go"})

    def test_replayed_signed_receipt_is_one_use_even_with_valid_signature(self):
        signed = self.receipt()
        self.assertEqual(self.verify(signed)["status"], "verified_uninstalled")
        result = self.verify(signed)
        self.assertEqual(result["status"], "blocked")
        self.assertIn("replay", result["reason"])

    def test_cross_task_context_and_generation_rejected_before_nonce_consumption(self):
        for field, other in (
            ("task_id", "task-B"), ("context_id", "context-B"),
            ("generation", "cg-generation-B"), ("nonce", "b" * 64),
        ):
            with self.subTest(field=field):
                altered = dict(self.challenge, **{field: other})
                self.assertEqual(self.verify(self.receipt(), altered)["status"], "blocked")

    def test_forged_or_extended_signature_is_rejected(self):
        signed = self.receipt()
        signed["expires_monotonic_ns"] += 50_000_000_000
        self.assertEqual(self.verify(signed)["status"], "blocked")
        signed = self.receipt()
        signed["signature"] = "0" * 128
        self.assertEqual(self.verify(signed)["status"], "blocked")

    def test_late_broker_response_is_rejected(self):
        expired = self.receipt(issued_monotonic_ns=1, expires_monotonic_ns=2)
        self.assertEqual(self.verify(expired)["status"], "blocked")

    def test_substituted_kernel_evaluator_uid_and_process_identity_rejected(self):
        signed = self.receipt()
        def substituted_uid(pid):
            return {**self.observer(pid), "uid": self.evaluator["evaluator_uid"] + 1}
        def substituted_binary(pid):
            return {**self.observer(pid), "executable": [18, 24, stat.S_IFREG | 0o755, 0]}
        self.assertEqual(self.verify(signed, observer=substituted_uid)["status"], "blocked")
        self.assertEqual(self.verify(signed, observer=substituted_binary)["status"], "blocked")

    def test_dead_evaluator_or_substituted_verifier_executable_rejected(self):
        signed = self.receipt()
        self.assertEqual(self.verify(signed, observer=lambda pid: (_ for _ in ()).throw(ProcessLookupError()))["status"], "blocked")
        signed = self.receipt(verifier_executable=[9, 8, stat.S_IFREG | 0o755, 0])
        self.assertEqual(self.verify(signed)["status"], "blocked")

    def test_corrupt_replay_ledger_fails_closed(self):
        (self.ledger / "used-nonces").write_text("broken-record\n", encoding="ascii")
        self.assertEqual(self.verify(self.receipt())["status"], "blocked")

    def test_nonce_record_survives_real_sigkill_and_process_restart(self):
        read_fd, write_fd = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(read_fd)
            result = _consume_once(self.ledger, "c" * 64)
            os.write(write_fd, result["status"].encode())
            os.kill(os.getpid(), signal.SIGKILL)
            os._exit(2)
        os.close(write_fd)
        try:
            self.assertEqual(os.read(read_fd, 64), b"recorded")
            _, status = os.waitpid(child, 0)
            self.assertTrue(os.WIFSIGNALED(status))
            self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
            result = _consume_once(self.ledger, "c" * 64)
            self.assertEqual(result["status"], "blocked", result)
            self.assertIn("replay", result["reason"])
        finally:
            os.close(read_fd)

    def test_mock_broker_never_opens_installed_protected_admission(self):
        from types import SimpleNamespace
        with patch.object(acceptance_cli.sys, "flags", SimpleNamespace(isolated=1, no_site=1)), \
             patch.object(acceptance_cli.sys, "prefix", "/usr"), \
             patch.object(acceptance_cli.sys, "base_prefix", "/usr"), \
             patch.object(acceptance_cli, "_protected_path", return_value=None), \
             patch.object(acceptance_cli, "probe_broker", return_value={"status": "connected_unverified"}):
            result = acceptance_cli._installed_verifier_admission_check()
        self.assertEqual(result["status"], "blocked", result)


if __name__ == "__main__":
    unittest.main()
