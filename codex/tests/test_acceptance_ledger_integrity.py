"""Crash/tamper regression: a valid early receipt never masks corrupt tail records."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from acceptance_reconcile import lookup, receipt_path, record_launch, reconcile


class LedgerHistoryValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="orchestra-ledger-integrity-")
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name) / "home"
        self.identity = {
            "t3_thread_id": "thread", "receipt": "receipt", "task_id": "task",
            "phase": "review", "commit": "a" * 40, "worktree": "/tmp/checkout",
        }
        self.assertEqual(record_launch(**self.identity, home=self.home)["status"], "recorded")
        self.ledger = receipt_path(self.home)
        self.original = self.ledger.read_bytes()

    def _append(self, raw: bytes):
        with self.ledger.open("ab") as f:
            f.write(raw)
        return self.ledger.read_bytes()

    def _assert_corrupt_blocks_without_writes(self, corrupted):
        same = record_launch(**self.identity, home=self.home)
        different = record_launch(**{**self.identity, "receipt": "other"}, home=self.home)
        replay = reconcile("thread", "receipt", **{k: self.identity[k]
                    for k in ("task_id", "phase", "commit", "worktree")}, home=self.home)
        self.assertEqual(same["status"], "blocked")
        self.assertEqual(different["status"], "blocked")
        self.assertEqual(replay["status"], "blocked")
        self.assertEqual(lookup("thread", "receipt", home=self.home)["status"], "blocked")
        self.assertEqual(self.ledger.read_bytes(), corrupted)

    def test_torn_tail_does_not_allow_early_matching_replay(self):
        self._assert_corrupt_blocks_without_writes(self._append(b'{"receipt":"torn'))

    def test_non_object_tail_is_not_a_valid_receipt(self):
        self._assert_corrupt_blocks_without_writes(self._append(b'[]\n'))

    def test_incomplete_record_tail_is_rejected(self):
        self._assert_corrupt_blocks_without_writes(self._append(b'{"receipt":"other"}\n'))

    def test_duplicate_receipt_with_changed_identity_is_rejected(self):
        duplicated = json.loads(self.original)
        duplicated["task_id"] = "forged"
        self._assert_corrupt_blocks_without_writes(
            self._append((json.dumps(duplicated) + "\n").encode()))

    def test_duplicate_receipt_with_same_identity_is_also_ambiguous(self):
        self._assert_corrupt_blocks_without_writes(self._append(self.original))

    def test_invalid_timestamp_does_not_override_earlier_record(self):
        new = json.loads(self.original)
        new["receipt"] = "other"
        new["recorded_at"] = float("nan")
        self._assert_corrupt_blocks_without_writes(
            self._append((json.dumps(new) + "\n").encode()))

    def test_duplicate_json_keys_fail_closed(self):
        self._assert_corrupt_blocks_without_writes(
            self._append(self.original.rstrip(b"\n").replace(
                b'"receipt": "receipt",',
                b'"receipt": "receipt", "receipt": "other",') + b"\n"))

    def test_overlarge_timestamp_fails_closed(self):
        new = json.loads(self.original)
        new["receipt"] = "other"
        new["recorded_at"] = 10 ** 1000
        self._assert_corrupt_blocks_without_writes(
            self._append((json.dumps(new) + "\n").encode()))

    def test_valid_history_still_replays_and_appends_new_receipts(self):
        self.assertEqual(record_launch(**self.identity, home=self.home)["status"], "duplicate")
        self.assertEqual(reconcile("thread", "receipt", **{k: self.identity[k]
                    for k in ("task_id", "phase", "commit", "worktree")}, home=self.home)["status"], "replayed")
        self.assertEqual(self.ledger.read_bytes(), self.original)
        self.assertEqual(record_launch(**{**self.identity, "receipt": "other"}, home=self.home)["status"], "recorded")
        self.assertEqual(len(self.ledger.read_text().splitlines()), 2)


if __name__ == "__main__":
    unittest.main()
