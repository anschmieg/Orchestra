from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import acceptance_cli


class VerifierTrustBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="orchestra-verifier-trust-")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name) / "verifier"
        self.home.mkdir(mode=0o700)
        self.grants = self.home / "grants.json"
        self.grants.write_text('{"grants":["verify_evidence"]}\n', encoding="utf-8")
        self.grants.chmod(0o600)
        self.keyring = self.home / "keyring.json"
        self.keyring.write_text('{"verifier_public_key":null,"trusted":[]}\n', encoding="utf-8")
        self.keyring.chmod(0o600)
        self.patches = (
            patch.object(acceptance_cli, "VERIFIER_HOME", self.home),
            patch.object(acceptance_cli, "VERIFIER_UID", os.getuid()),
        )
        for ctx in self.patches:
            ctx.start()
            self.addCleanup(ctx.stop)

    def assert_denied(self, *reason_parts):
        result = acceptance_cli._verifier_principal_check()
        self.assertEqual(result["status"], "blocked", result)
        for part in reason_parts:
            self.assertIn(part, result["reason"])

    def test_control_fixture_is_not_itself_a_proof_of_isolation(self):
        result = acceptance_cli._verifier_principal_check()
        self.assertEqual(result["status"], "blocked")
        self.assertIn("ancestor", result["reason"])

    def test_group_writable_trust_root_is_rejected(self):
        self.home.chmod(0o770)
        self.assert_denied("trust root")

    def test_world_writable_trust_root_is_rejected(self):
        self.home.chmod(0o777)
        self.assert_denied("trust root")

    def test_symlinked_trust_root_is_rejected(self):
        alias = Path(self.temp.name) / "attacker-home"
        alias.symlink_to(self.home, target_is_directory=True)
        with patch.object(acceptance_cli, "VERIFIER_HOME", alias):
            self.assert_denied("trust root")

    def test_attacker_writable_keyring_is_rejected(self):
        self.keyring.chmod(0o666)
        self.assert_denied("keyring")

    def test_symlinked_keyring_is_rejected(self):
        elsewhere = Path(self.temp.name) / "attacker-keyring.json"
        elsewhere.write_text(self.keyring.read_text(), encoding="utf-8")
        self.keyring.unlink()
        self.keyring.symlink_to(elsewhere)
        self.assert_denied("keyring")

    def test_absent_protected_keyring_is_rejected(self):
        self.keyring.unlink()
        self.assert_denied("keyring")

    def test_symlinked_grants_are_rejected(self):
        elsewhere = self.home / "other-grants.json"
        elsewhere.write_text(self.grants.read_text(), encoding="utf-8")
        elsewhere.chmod(0o600)
        self.grants.unlink()
        self.grants.symlink_to(elsewhere)
        self.assert_denied("grants")

    def test_effective_uid_mismatch_is_rejected(self):
        with patch.object(acceptance_cli.os, "geteuid", return_value=os.getuid() + 1):
            self.assert_denied("verifier UID")


if __name__ == "__main__":
    unittest.main()
