from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from acceptance_reconcile import record_launch, reconcile, list_launches
from acceptance_keyring import generate_keypair


class ConcurrencyRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(prefix="orchestra-conc-"))

    def test_concurrent_record_same_receipt_deduplicates(self):
        errors = []
        def record():
            try:
                record_launch(
                    t3_thread_id="t3:concurrent", receipt="receipt-concurrent",
                    task_id="task-1", phase="implement", commit="a" * 40,
                    home=self.home,
                )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=record) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0)
        launches = list_launches(home=self.home)
        self.assertEqual(len(launches), 1)

    def test_reconcile_unknown_fails_closed(self):
        result = reconcile("t3:ghost", "missing", home=self.home)
        self.assertEqual(result["status"], "blocked")

    def test_reconcile_after_record_replays(self):
        record_launch(
            t3_thread_id="t3:replay", receipt="r1", task_id="task-1",
            phase="implement", commit="b" * 40, home=self.home,
        )
        result = reconcile("t3:replay", "r1", home=self.home)
        self.assertEqual(result["status"], "replayed")
        self.assertEqual(result["task_id"], "task-1")

    def test_concurrent_reconcile_same_receipt_consistent(self):
        record_launch(
            t3_thread_id="t3:concurrent2", receipt="r2", task_id="task-2",
            phase="review", commit="c" * 40, home=self.home,
        )
        results = []
        def rec():
            results.append(reconcile("t3:concurrent2", "r2", home=self.home))
        threads = [threading.Thread(target=rec) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        for r in results:
            self.assertEqual(r["status"], "replayed")

    def test_jsonl_append_atomic_via_os_write(self):
        record_launch(
            t3_thread_id="t3:atomic", receipt="r3", task_id="task-3",
            phase="implement", commit="d" * 40, home=self.home,
        )
        launches = list_launches(home=self.home)
        self.assertEqual(len(launches), 1)
        lines = (self.home / "reconcile" / "receipts.jsonl").read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 1)
        entry = json.loads(lines[0])
        self.assertEqual(entry["receipt"], "r3")


if __name__ == "__main__":
    unittest.main()
