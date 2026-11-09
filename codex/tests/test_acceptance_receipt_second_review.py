from __future__ import annotations
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from acceptance_receipt import _consume_once


class IndependentReceiptCrashSafetyReview(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="independent-receipt-review-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "ledger"
        self.root.mkdir(mode=0o700)

    def test_missing_operator_provisioned_ledger_must_fail_closed(self):
        result = _consume_once(self.root, "f" * 64)
        self.assertEqual(result["status"], "blocked", result)
        self.assertFalse((self.root / "used-nonces").exists())

    def test_deleted_consumption_ledger_must_not_reauthorize_replay(self):
        ledger = self.root / "used-nonces"
        ledger.touch(mode=0o600)
        self.assertEqual(_consume_once(self.root, "b" * 64)["status"], "recorded")
        ledger.unlink()
        result = _consume_once(self.root, "b" * 64)
        self.assertEqual(result["status"], "blocked", result)

    def test_symlinked_ledger_to_attacker_file_must_block(self):
        target = self.root / "foreign"
        target.write_text("x\n", encoding="ascii")
        (self.root / "used-nonces").symlink_to(target)
        self.assertEqual(_consume_once(self.root, "e" * 64)["status"], "blocked")

    def test_partial_record_after_crash_must_block_without_truncation(self):
        ledger = self.root / "used-nonces"
        ledger.write_text("123", encoding="ascii")
        result = _consume_once(self.root, "e" * 64)
        self.assertEqual(result["status"], "blocked", result)
        self.assertEqual(ledger.read_text(), "123")


if __name__ == "__main__":
    unittest.main()
