from __future__ import annotations
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "codex" / "scripts"))
import acceptance_cli as cli

class OperatorPinnedInstalledAdmission(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.pub = self.key.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH, format=serialization.PublicFormat.OpenSSH
        ).decode("ascii")
        self.install = {
            "schema": 1, "installation_id": "installation-A", "generation": "generation-A",
            "task_id": "task-A", "context_id": "context-A",
            "broker_socket": "/run/orchestra-acceptance/broker.sock",
            "broker_uid": 0, "broker_executable": [9, 11, stat.S_IFREG | 0o755, 0],
            "socket_identity": [2, 3, 0, stat.S_IFSOCK | 0o660],
            "verifier_uid": 999, "evaluator_uid": 1001,
            "broker_public_key": self.pub,
        }

    def _installed(self, *, receipt=None, endpoint=None):
        from unittest.mock import Mock
        receipt = receipt or {"status": "verified_uninstalled"}
        observed_endpoint = endpoint if endpoint is not None else tuple(self.install["socket_identity"])
        with patch.object(cli.sys, "flags", type("Flags", (), {"isolated": 1, "no_site": 1})()), \
             patch.object(cli.sys, "prefix", "/usr"), \
             patch.object(cli.sys, "base_prefix", "/usr"), \
             patch.object(cli, "_protected_path", return_value=None), \
             patch.object(cli, "_load_operator_installation", return_value={"status": "ok", "installation": self.install}), \
             patch.object(cli, "_endpoint_identity", return_value=observed_endpoint), \
             patch.object(cli, "_installed_boundary_snapshot", return_value={"status": "ok", "identity": {"fixed": True}}), \
             patch.object(cli, "_protected_receipt_at", return_value=receipt) as challenge:
            result = cli._installed_verifier_admission_check()
        return result, challenge

    def test_cli_binds_pinned_manifest_key_generation_and_live_broker_identity(self):
        result, challenge = self._installed()
        self.assertEqual(result["status"], "blocked", result)
        self.assertIn("positive", result["reason"])
        challenge.assert_called_once()
        args, kwargs = challenge.call_args
        self.assertEqual(args[0], cli.BROKER_SOCKET)
        self.assertEqual(kwargs["task_id"], "task-A")
        self.assertEqual(kwargs["context_id"], "context-A")
        self.assertEqual(kwargs["generation"], "generation-A")
        self.assertEqual(kwargs["expected_broker_executable"], self.install["broker_executable"])
        self.assertEqual(tuple(kwargs["expected_endpoint_identity"]), tuple(self.install["socket_identity"]))
        self.assertEqual(kwargs["broker_verify_key"].public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw),
            self.key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
        self.assertEqual(kwargs["ledger_dir"], cli.BROKER_LEDGER)

    def test_root_like_transport_and_forged_accepted_response_never_grant_go(self):
        result, challenge = self._installed(receipt={"status": "accepted", "claim": "root-broker"})
        self.assertEqual(result["status"], "blocked", result)
        challenge.assert_called_once()

    def test_same_broker_socket_path_with_replaced_inode_is_rejected_before_receipt(self):
        result, challenge = self._installed(endpoint=(2, 999, 0, stat.S_IFSOCK | 0o660))
        self.assertEqual(result["status"], "blocked", result)
        self.assertIn("socket", result["reason"])
        challenge.assert_not_called()

    def test_rotated_installation_generation_stale_signature_cannot_grant_go(self):
        self.install["generation"] = "generation-B"
        result, challenge = self._installed(receipt={
            "status": "blocked", "reason": "signed broker receipt challenge binding mismatch: generation"})
        self.assertEqual(result["status"], "blocked", result)
        self.assertEqual(challenge.call_args.kwargs["generation"], "generation-B")

    def test_unprivileged_owner_key_manifest_cannot_be_loaded_as_operator_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "broker-installation.json"
            source.write_text('{"broker_public_key":"attacker"}', encoding="utf-8")
            with patch.object(cli, "BROKER_INSTALLATION", source):
                result = cli._load_operator_installation()
        self.assertEqual(result["status"], "blocked", result)
        self.assertIn("broker installation", result["reason"])

    def test_protected_ledger_and_broker_parent_are_required_before_admission(self):
        def protect(path, *, label, owners):
            if path == cli.BROKER_LEDGER:
                return "replay ledger installation is absent"
            return None
        with patch.object(cli.sys, "flags", type("Flags", (), {"isolated": 1, "no_site": 1})()), \
             patch.object(cli.sys, "prefix", "/usr"), \
             patch.object(cli.sys, "base_prefix", "/usr"), \
             patch.object(cli, "_protected_path", side_effect=protect), \
             patch.object(cli, "_load_operator_installation", return_value={"status": "ok", "installation": self.install}), \
             patch.object(cli, "_endpoint_identity", return_value=tuple(self.install["socket_identity"])), \
             patch.object(cli, "_protected_receipt_at") as exchange:
            result = cli._installed_verifier_admission_check()
        self.assertEqual(result["status"], "blocked")
        exchange.assert_not_called()

if __name__ == "__main__":
    unittest.main()
