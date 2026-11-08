#!/usr/bin/env python3

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from acceptance_reconcile import list_launches, lookup, record_launch, reconcile


class ReconcileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(prefix="orchestra-reconcile-"))

    def test_record_then_lookup(self) -> None:
        result = record_launch(
            t3_thread_id="t1",
            receipt="r1",
            task_id="task-1",
            phase="implement",
            commit="a" * 40, worktree="/tmp/task-record", 
            home=self.home,
        )
        self.assertEqual(result["status"], "recorded")
        found = lookup("t1", "r1", home=self.home)
        self.assertEqual(found["status"], "found")
        self.assertEqual(found["task_id"], "task-1")

    def test_duplicate_receipt_is_not_replayed(self) -> None:
        record_launch(
            t3_thread_id="t1", receipt="r1", task_id="task-1",
            phase="implement", commit="a" * 40, worktree="/tmp/task-record",  home=self.home,
        )
        second = record_launch(
            t3_thread_id="t1", receipt="r1", task_id="task-1",
            phase="implement", commit="a" * 40, worktree="/tmp/task-record",  home=self.home,
        )
        self.assertEqual(second["status"], "duplicate")

    def test_reconcile_unknown_fails_closed(self) -> None:
        result = reconcile("ghost", "missing", home=self.home)
        self.assertEqual(result["status"], "blocked")
        self.assertIn("duplicate", result["reason"])

    def test_reconcile_known_replays(self) -> None:
        record_launch(
            t3_thread_id="t1", receipt="r1", task_id="task-1",
            phase="implement", commit="a" * 40, worktree="/tmp/task-1", home=self.home,
        )
        result = reconcile(
            "t1", "r1", task_id="task-1", phase="implement",
            commit="a" * 40, worktree="/tmp/task-1", home=self.home,
        )
        self.assertEqual(result["status"], "replayed")

    def test_invalid_commit_rejected(self) -> None:
        result = record_launch(
            t3_thread_id="t1", receipt="r1", task_id="task-1",
            phase="implement", commit="short", home=self.home,
        )
        self.assertEqual(result["status"], "blocked")


    def test_receipt_reuse_with_changed_context_is_blocked(self) -> None:
        original = dict(t3_thread_id="t1", receipt="r1", task_id="task-1",
                        phase="implement", commit="a" * 40, worktree="/tmp/task-1")
        self.assertEqual(record_launch(**original, home=self.home)["status"], "recorded")
        self.assertEqual(record_launch(**original, home=self.home)["status"], "duplicate")
        for field, replacement in (
            ("task_id", "task-2"), ("phase", "review"),
            ("commit", "b" * 40), ("worktree", "/tmp/task-2"),
            ("t3_thread_id", "t2"),
        ):
            changed = {**original, field: replacement}
            self.assertEqual(record_launch(**changed, home=self.home)["status"], "blocked", field)
            if field != "t3_thread_id":
                self.assertEqual(
                    reconcile("t1", "r1", task_id=changed["task_id"],
                              phase=changed["phase"], commit=changed["commit"],
                              worktree=changed["worktree"], home=self.home)["status"],
                    "blocked", field,
                )

    def test_replay_without_full_context_is_blocked(self) -> None:
        record_launch(
            t3_thread_id="t1", receipt="r1", task_id="task-1", phase="review",
            commit="a" * 40, worktree="/tmp/task-1", home=self.home,
        )
        self.assertEqual(reconcile("t1", "r1", home=self.home)["status"], "blocked")

    def test_non_hex_commit_and_corrupt_receipts_blocked(self) -> None:
        blocked = record_launch(
            t3_thread_id="t1", receipt="r1", task_id="task-1", phase="review",
            commit="z" * 40, worktree="/tmp/task-1", home=self.home,
        )
        self.assertEqual(blocked["status"], "blocked")
        receipt_file = self.home / "reconcile" / "receipts.jsonl"
        receipt_file.parent.mkdir(parents=True, exist_ok=True)
        receipt_file.write_text("invalid json\\n", encoding="utf-8")
        blocked = record_launch(
            t3_thread_id="t1", receipt="r1", task_id="task-1", phase="review",
            commit="a" * 40, worktree="/tmp/task-1", home=self.home,
        )
        self.assertEqual(blocked["status"], "blocked")
        self.assertEqual(reconcile("t1", "r1", home=self.home)["status"], "blocked")

    def test_list_returns_all_launches(self) -> None:
        record_launch(
            t3_thread_id="t1", receipt="r1", task_id="task-1",
            phase="implement", commit="a" * 40, worktree="/tmp/task-record",  home=self.home,
        )
        record_launch(
            t3_thread_id="t2", receipt="r2", task_id="task-2",
            phase="review", commit="b" * 40, worktree="/tmp/task-record",  home=self.home,
        )
        launches = list_launches(home=self.home)
        self.assertEqual(len(launches), 2)


if __name__ == "__main__":
    unittest.main()
