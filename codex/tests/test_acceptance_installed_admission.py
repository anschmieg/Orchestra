from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import acceptance_cli


class InstalledVerifierAdmissionTests(unittest.TestCase):
    """Rootless rejection tests; fake root metadata is NOT an installed-root proof."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="orchestra-admission-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.parent = self.root / "writable-parent"
        self.parent.mkdir(mode=0o777)
        self.parent.chmod(0o777)
        self.home = self.parent / "verifier"
        self.home.mkdir(mode=0o700)
        self.grants = self.home / "grants.json"
        self.grants.write_text('{"grants":["verify_evidence"]}\n', encoding="utf-8")
        self.grants.chmod(0o600)
        self.keyring = self.home / "keyring.json"
        self.keyring.write_text('{"trusted":[]}\n', encoding="utf-8")
        self.keyring.chmod(0o600)
        for target, value in (("VERIFIER_HOME", self.home), ("VERIFIER_UID", os.getuid())):
            ctx = patch.object(acceptance_cli, target, value)
            ctx.start()
            self.addCleanup(ctx.stop)

    def test_writable_ancestor_blocks_even_when_leaf_files_are_private(self):
        result = acceptance_cli._verifier_principal_check()
        self.assertEqual(result["status"], "blocked", result)
        self.assertIn("ancestor", result["reason"])

    def _fake_root_stat(self, path, *, bad_path=None, bad_mode=None, bad_uid=None):
        key = str(path)
        is_file = key.endswith(".py")
        mode = (stat.S_IFREG | 0o755) if is_file else (stat.S_IFDIR | 0o755)
        uid = 0
        if key == bad_path:
            mode = bad_mode if bad_mode is not None else mode
            uid = bad_uid if bad_uid is not None else uid
        return SimpleNamespace(st_mode=mode, st_uid=uid)

    def test_attacker_writable_entrypoint_parent_rejected_with_fake_stat(self):
        target = Path("/opt/orchestra/bin/acceptance_cli.py")
        with patch.object(acceptance_cli.os, "lstat",
                          side_effect=lambda p: self._fake_root_stat(
                              p, bad_path="/opt/orchestra", bad_mode=stat.S_IFDIR | 0o777)):
            reason = acceptance_cli._protected_path(target, label="entrypoint", owners=(0,))
        self.assertIn("ancestor", reason)
        self.assertIn("entrypoint", reason)

    def test_swappable_interpreter_file_rejected_with_fake_stat(self):
        target = Path("/opt/python/bin/python3.py")
        with patch.object(acceptance_cli.os, "lstat",
                          side_effect=lambda p: self._fake_root_stat(
                              p, bad_path=str(target), bad_mode=stat.S_IFREG | 0o777)):
            reason = acceptance_cli._protected_path(target, label="interpreter", owners=(0,))
        self.assertIn("interpreter", reason)

    def test_interpreter_symlink_rejected_with_fake_stat(self):
        target = Path("/opt/python/bin/python3.py")
        with patch.object(acceptance_cli.os, "lstat",
                          side_effect=lambda p: self._fake_root_stat(
                              p, bad_path=str(target), bad_mode=stat.S_IFLNK | 0o777)):
            reason = acceptance_cli._protected_path(target, label="interpreter", owners=(0,))
        self.assertIn("interpreter", reason)

    def test_mismatched_verifier_identity_rejected(self):
        with patch.object(acceptance_cli, "VERIFIER_UID", os.getuid() + 1):
            result = acceptance_cli._verifier_principal_check()
        self.assertEqual(result["status"], "blocked")
        self.assertIn("verifier UID", result["reason"])

    def test_mutable_virtualenv_with_pth_is_not_admitted(self):
        with patch.object(acceptance_cli.sys, "flags", SimpleNamespace(isolated=1, no_site=1)), \
             patch.object(acceptance_cli.sys, "prefix", "/tmp/mutable-venv"), \
             patch.object(acceptance_cli.sys, "base_prefix", "/usr"):
            result = acceptance_cli._installed_verifier_admission_check()
        self.assertEqual(result["status"], "blocked")
        self.assertIn("virtual environment", result["reason"])

    def test_missing_isolated_no_site_startup_rejected(self):
        with patch.object(acceptance_cli.sys, "flags", SimpleNamespace(isolated=1, no_site=0)):
            result = acceptance_cli._installed_verifier_admission_check()
        self.assertEqual(result["status"], "blocked")
        self.assertIn("startup", result["reason"])

    def test_broker_transport_without_identity_attestation_rejected(self):
        with patch.object(acceptance_cli.sys, "flags", SimpleNamespace(isolated=1, no_site=1)), \
             patch.object(acceptance_cli.sys, "prefix", "/usr"), \
             patch.object(acceptance_cli.sys, "base_prefix", "/usr"), \
             patch.object(acceptance_cli, "_protected_path", return_value=None), \
             patch.object(acceptance_cli, "probe_broker", return_value={"status": "connected_unverified"}):
            result = acceptance_cli._installed_verifier_admission_check()
        self.assertEqual(result["status"], "blocked")
        self.assertIn("broker attestation", result["reason"])

    def test_fake_broker_claim_with_mismatched_uids_cannot_grant_go(self):
        with patch.object(acceptance_cli.sys, "flags", SimpleNamespace(isolated=1, no_site=1)), \
             patch.object(acceptance_cli.sys, "prefix", "/usr"), \
             patch.object(acceptance_cli.sys, "base_prefix", "/usr"), \
             patch.object(acceptance_cli, "_protected_path", return_value=None), \
             patch.object(acceptance_cli, "probe_broker",
                          return_value={"status": "ready", "verifier_uid": 123,
                                        "evaluator_uid": 123, "capabilities": []}):
            result = acceptance_cli._installed_verifier_admission_check()
        self.assertEqual(result["status"], "blocked")
        self.assertIn("broker", result["reason"])


if __name__ == "__main__":
    unittest.main()
