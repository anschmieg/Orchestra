from __future__ import annotations

import os
import stat
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "codex" / "scripts"))
sys.path.insert(0, str(ROOT / "codex" / "tests"))
import test_acceptance_rotation as rotation


class IndependentPostReceiptAdversarialReview(unittest.TestCase):
    """Additional unprivileged negatives. Never claims installed privileged GO."""

    def negative(self, tamper):
        fixture = rotation.RotationAcrossRefusedIPC(
            methodName="test_generation_manifest_replaced_while_ipc_is_refused")
        fixture.setUp()
        try:
            return fixture.refusal(lambda: tamper(fixture))
        finally:
            fixture.doCleanups()

    def test_executable_inode_pin_rotated_while_broker_refused(self):
        def tamper(f):
            f.manifest["broker_executable"][1] += 1
            f.write_manifest()
        reason = self.negative(tamper)
        self.assertIn("installation", reason)
        self.assertIn("changed", reason)

    def test_verifier_evaluator_separation_changed_while_broker_refused(self):
        def tamper(f):
            f.manifest["evaluator_uid"] = f.manifest["verifier_uid"]
            f.write_manifest()
        reason = self.negative(tamper)
        self.assertIn("installation", reason)
        self.assertIn("changed", reason)

    def test_protected_keyring_same_content_swapped_inode(self):
        def tamper(f):
            dest = f.home / "keyring.json"
            replacement = f.home / "replacement-keyring"
            replacement.write_bytes(dest.read_bytes())
            replacement.replace(dest)
        reason = self.negative(tamper)
        self.assertIn("installation", reason)
        self.assertIn("changed", reason)

    def test_kernel_cgroup_change_during_broker_refusal(self):
        moved = {"now": False}
        real_read = Path.read_bytes
        def read_bytes(path):
            if str(path) == "/proc/self/cgroup":
                return b"0::/after\n" if moved["now"] else b"0::/before\n"
            return real_read(path)
        with patch.object(Path, "read_bytes", read_bytes):
            reason = self.negative(lambda f: moved.__setitem__("now", True))
        self.assertIn("installation", reason)
        self.assertIn("changed", reason)


if __name__ == "__main__":
    unittest.main()
