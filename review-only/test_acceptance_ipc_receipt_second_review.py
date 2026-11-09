from __future__ import annotations

import json
import os
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path.cwd() / "codex" / "scripts"))
import acceptance_broker_ipc as ipc
import acceptance_cli
import acceptance_gate


class IndependentProtectedAdmissionReview(unittest.TestCase):
    def _installed(self, claim):
        with patch.object(acceptance_cli.sys, "flags", SimpleNamespace(isolated=1, no_site=1)), \
             patch.object(acceptance_cli.sys, "prefix", "/usr"), \
             patch.object(acceptance_cli.sys, "base_prefix", "/usr"), \
             patch.object(acceptance_cli, "_protected_path", return_value=None), \
             patch.object(acceptance_cli, "probe_broker", return_value=claim):
            return acceptance_cli._installed_verifier_admission_check()

    def test_simulated_signed_broker_cannot_satisfy_installed_admission(self):
        with patch.object(ipc, "_protected_receipt_at",
                          return_value={"status": "verified_uninstalled"}):
            result = self._installed({"status": "connected_unverified"})
        self.assertEqual(result["status"], "blocked", result)
        self.assertNotIn(result["status"], {"ok", "accepted", "go"})

    def test_forged_broker_accepted_status_cannot_satisfy_installed_admission(self):
        result = self._installed({"status": "accepted",
                                  "verifier_uid": acceptance_cli.VERIFIER_UID,
                                  "evaluator_uid": acceptance_cli.VERIFIER_UID + 1})
        self.assertEqual(result["status"], "blocked", result)

    def test_untrusted_broker_claim_cannot_execute_protected_gate(self):
        with patch.object(ipc, "_protected_receipt_at",
                          return_value={"status": "verified_uninstalled"}):
            result = acceptance_gate.run_gate(Path("/tmp/untrusted"),
                    {"gate_id": "g", "contract": "c",
                     "checks": [{"name": "danger", "command": ["sh", "-c", "exit 0"]}]},
                    "a" * 40)
        self.assertEqual(result["status"], "blocked", result)
        self.assertEqual(result["checks"][0]["status"], "blocked")

    def test_uninstalled_broker_cannot_consume_live_admission_receipt(self):
        result = ipc._protected_receipt_at(
            Path("/tmp/unprivileged.sock"), task_id="task-A", context_id="context-A",
            generation="generation-A", broker_verify_key=object(),
            ledger_dir=Path("/tmp/missing-ledger"))
        self.assertEqual(result["status"], "blocked", result)


    @unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "pidfd_open"),
                         "Linux PIDFD required")
    def test_real_sigkill_broker_peer_blocks_inherited_late_signed_reply(self):
        child = subprocess.Popen(
            [sys.executable, "-c", "import time;time.sleep(30)"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        key = Ed25519PrivateKey.generate()
        evaluator = {
            "evaluator_pid": os.getpid() + 9000,
            "evaluator_uid": os.getuid() + 2300,
            "evaluator_executable": [7, 15, stat.S_IFREG | 0o755, 0],
        }

        class LateReply:
            def __init__(self):
                self.reply = None
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def settimeout(self, *_): pass
            def connect(self, *_): pass
            def getsockopt(self, _level, option, _length):
                if option == ipc.SO_PEERPIDFD:
                    return struct.pack("i", os.pidfd_open(child.pid, 0))
                return struct.pack("3i", child.pid, 0, 0)
            def sendall(self, payload):
                body = {**json.loads(payload), **evaluator}
                signature = key.sign(json.dumps(
                    body, sort_keys=True, separators=(",", ":")).encode()).hex()
                self.reply = (json.dumps(
                    {**body, "signature": signature}, sort_keys=True) + "\\n").encode()
                child.kill()
                child.wait(timeout=5)
            def recv(self, _size):
                value, self.reply = self.reply, b""
                return value

        try:
            with tempfile.TemporaryDirectory() as directory:
                ledger = Path(directory) / "ledger"
                ledger.mkdir(mode=0o700)
                (ledger / "used-nonces").touch(mode=0o600)
                with patch.object(ipc, "_trusted_endpoint", return_value=None), \\
                     patch.object(ipc, "_endpoint_identity", return_value=(3, 4)), \\
                     patch.object(ipc.socket, "socket", return_value=LateReply()), \\
                     patch.object(ipc.secrets, "token_hex", return_value="e" * 64):
                    result = ipc._protected_receipt_at(
                        ipc.BROKER_SOCKET, task_id="task-A",
                        context_id="context-A", generation="generation-A",
                        broker_verify_key=key.public_key(), ledger_dir=ledger)
                self.assertEqual(result["status"], "blocked", result)
                self.assertIn("exited", result["reason"])
                self.assertEqual((ledger / "used-nonces").read_text(), "")
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)

if __name__ == "__main__":
    unittest.main()
