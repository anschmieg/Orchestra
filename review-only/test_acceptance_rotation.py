from __future__ import annotations

import json
import os
import socket
import stat
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "codex" / "scripts"))
import acceptance_cli as cli

# Adversarial unprivileged NEGATIVES only: no root installation, broker, or GO simulated.
CODE_FILES = (
    "acceptance_cli.py", "acceptance_gate.py", "acceptance_broker_ipc.py",
    "acceptance_keyring.py", "acceptance_policy.py", "acceptance_reconcile.py",
    "acceptance_evidence.py", "acceptance_receipt.py",
)


class RotationAcrossRefusedIPC(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manifest_path = self.root / "broker-installation.json"
        self.ledger = self.root / "admissions"
        self.ledger.mkdir()
        self.src = self.root / "installed-code"
        self.src.mkdir()
        for name in CODE_FILES:
            (self.src / name).write_text("# immutable placeholder\n")
        self.socket_path = self.root / "broker.sock"
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.socket_path))
        self.addCleanup(self.listener.close)
        self.manifest = {
            "schema": 1, "installation_id": "unprivileged-test-only",
            "generation": "gen-A", "task_id": "task", "context_id": "context",
            "broker_socket": str(self.socket_path), "broker_uid": 0,
            "broker_executable": [1, 2, stat.S_IFREG | 0o755, 0],
            "socket_identity": list(self.socket_id()),
            "verifier_uid": 999, "evaluator_uid": 1001,
            "broker_public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        }
        self.write_manifest()

    def socket_id(self):
        s = os.lstat(self.socket_path)
        return s.st_dev, s.st_ino, s.st_uid, s.st_mode

    def write_manifest(self):
        self.manifest_path.write_text(json.dumps(self.manifest, sort_keys=True))

    def refusal(self, tamper):
        def exchange(*_args, **_kwargs):
            tamper()
            return {"status": "blocked", "reason": "unprivileged negative broker refusal"}
        def fake_load():
            # This fixture reads attacker-controlled data; it is NOT protected installation.
            return {"status": "ok", "installation": json.loads(self.manifest_path.read_text())}
        def endpoint(_path):
            return self.socket_id()
        with ExitStack() as stack:
            stack.enter_context(patch.object(cli.sys, "flags", type("Flags", (), {"isolated": 1, "no_site": 1})()))
            stack.enter_context(patch.object(cli.sys, "prefix", "/usr"))
            stack.enter_context(patch.object(cli.sys, "base_prefix", "/usr"))
            stack.enter_context(patch.object(cli, "BROKER_INSTALLATION", self.manifest_path))
            stack.enter_context(patch.object(cli, "BROKER_LEDGER", self.ledger))
            stack.enter_context(patch.object(cli, "BROKER_SOCKET", self.socket_path))
            stack.enter_context(patch.object(cli, "HERE", self.src))
            stack.enter_context(patch.object(cli, "_protected_path", return_value=None))
            stack.enter_context(patch.object(cli, "_load_operator_installation", side_effect=fake_load))
            stack.enter_context(patch.object(cli, "_endpoint_identity", side_effect=endpoint))
            call = stack.enter_context(patch.object(cli, "_protected_receipt_at", side_effect=exchange))
            result = cli._installed_verifier_admission_check()
        self.assertEqual(call.call_count, 1, result)
        self.assertEqual(result["status"], "blocked", result)
        return result["reason"].lower()

    def test_generation_manifest_replaced_while_ipc_is_refused(self):
        def change():
            self.manifest["generation"] = "gen-B"
            self.write_manifest()
        reason = self.refusal(change)
        self.assertIn("installation", reason)
        self.assertIn("changed", reason)

    def test_ed25519_public_key_rotated_while_ipc_is_refused(self):
        def change():
            self.manifest["broker_public_key"] = self.manifest["broker_public_key"][:-1] + "B"
            self.write_manifest()
        reason = self.refusal(change)
        self.assertIn("installation", reason)
        self.assertIn("changed", reason)

    def test_socket_inode_replaced_after_broker_refusal(self):
        def change():
            self.listener.close()
            self.socket_path.unlink()
            self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.listener.bind(str(self.socket_path))
        reason = self.refusal(change)
        self.assertIn("installation", reason)
        self.assertIn("changed", reason)

    def test_durable_replay_ledger_replaced_after_broker_refusal(self):
        def change():
            self.ledger.rename(self.root / "old-admissions")
            self.ledger.mkdir()
        reason = self.refusal(change)
        self.assertIn("installation", reason)
        self.assertIn("changed", reason)

    def test_verifier_code_inode_replaced_after_broker_refusal(self):
        def change():
            replacement = self.src / "replacement"
            replacement.write_text("# different immutable code\n")
            replacement.replace(self.src / "acceptance_gate.py")
        reason = self.refusal(change)
        self.assertIn("installation", reason)
        self.assertIn("changed", reason)

    def test_manifest_same_bytes_replaced_inode_after_broker_refusal(self):
        def change():
            replacement = self.root / "replacement.json"
            replacement.write_bytes(self.manifest_path.read_bytes())
            replacement.replace(self.manifest_path)
        reason = self.refusal(change)
        self.assertIn("installation", reason)
        self.assertIn("changed", reason)


if __name__ == "__main__":
    unittest.main()
