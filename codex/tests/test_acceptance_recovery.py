#!/usr/bin/env python3

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from acceptance_gate import run_gate
from acceptance_reconcile import list_launches, record_launch, reconcile


class DuplicateRequestRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(prefix="orchestra-recovery-"))

    def test_duplicate_launch_replays_not_duplicates(self) -> None:
        first = record_launch(
            t3_thread_id="t3:abc", receipt="receipt-1", task_id="task-1",
            phase="implement", commit="a" * 40, home=self.home,
        )
        self.assertEqual(first["status"], "recorded")
        second = record_launch(
            t3_thread_id="t3:abc", receipt="receipt-1", task_id="task-1",
            phase="implement", commit="a" * 40, home=self.home,
        )
        self.assertEqual(second["status"], "duplicate")
        self.assertEqual(len(list_launches(home=self.home)), 1)

    def test_reconcile_after_restart_replays(self) -> None:
        record_launch(
            t3_thread_id="t3:restart", receipt="r", task_id="task-2",
            phase="review", commit="b" * 40, worktree="/tmp/restart", home=self.home,
        )
        result = reconcile(
            "t3:restart", "r", task_id="task-2", phase="review",
            commit="b" * 40, worktree="/tmp/restart", home=self.home,
        )
        self.assertEqual(result["status"], "replayed")
        self.assertEqual(result["task_id"], "task-2")

    def test_unknown_launch_after_restart_fails_closed(self) -> None:
        result = reconcile("t3:ghost", "missing", home=self.home)
        self.assertEqual(result["status"], "blocked")
        self.assertIn("duplicate", result["reason"])


class CrashAndTimeoutRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Path(tempfile.mkdtemp(prefix="orchestra-crashrepo-"))
        subprocess.run(["git", "-C", str(self.repo), "init", "-q", "-b", "main"], check=True)
        (self.repo / "x.txt").write_text("x\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "add", "x.txt"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-q", "-m", "init"], check=True)

    def test_crashed_check_is_blocked_not_passed(self) -> None:
        spec = {
            "gate_id": "g",
            "contract": "crash",
            "checks": [{"name": "crash", "command": [sys.executable, "-c", "raise SystemExit(137)"]}],
        }
        result = run_gate(self.repo, spec, "HEAD")
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["checks"][0]["status"], "failed")

    def test_unstartable_check_is_blocked(self) -> None:
        spec = {
            "gate_id": "g",
            "contract": "missing",
            "checks": [{"name": "missing", "command": ["/no/such/binary/here"]}],
        }
        result = run_gate(self.repo, spec, "HEAD")
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["checks"][0]["status"], "blocked")

    def test_passing_check_is_accepted(self) -> None:
        spec = {
            "gate_id": "g",
            "contract": "ok",
            "checks": [{"name": "ok", "command": [sys.executable, "-c", "pass"]}],
        }
        result = run_gate(self.repo, spec, "HEAD")
        self.assertEqual(result["status"], "accepted")


if __name__ == "__main__":
    unittest.main()
