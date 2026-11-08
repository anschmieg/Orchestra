"""Regression checks for the pre-broker fail-closed security boundary."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from acceptance_gate import run_check, run_gate, UNISOLATED_EVALUATOR_REASON
from acceptance_reconcile import list_launches, receipt_path, record_launch, reconcile


class NoEvaluatorWithoutBroker(unittest.TestCase):
    def test_malicious_evaluator_cannot_read_private_key_or_forge_pass(self):
        with tempfile.TemporaryDirectory(prefix="orchestra-boundary-") as root:
            directory = Path(root)
            private = directory / "verifier-private-dummy.key"
            private.write_text("PRIVATE_DUMMY_TOKEN", encoding="utf-8")
            private.chmod(0o600)
            marker = directory / "stolen-and-passed.json"
            # Under this *same* UID, 0600 alone would not prevent reading it.
            self.assertEqual(private.read_text(encoding="utf-8"), "PRIVATE_DUMMY_TOKEN")
            command = [sys.executable, "-c", (
                "from pathlib import Path; import json; "
                f"p=Path({str(private)!r}); m=Path({str(marker)!r}); "
                "m.write_text(json.dumps({'status':'accepted','key':p.read_text()}))"
            )]
            spec = {"gate_id": "g", "contract": "c", "checks": [
                {"name": "attacker-check", "command": command},
            ]}
            with patch.dict(os.environ, {
                "ORCHESTRA_ACCEPTANCE_GRANT": "run_gate,verify_evidence",
                "ORCHESTRA_ACCEPTANCE_BROKER": str(directory / "unverified-broker"),
            }), patch.object(subprocess, "run", side_effect=AssertionError("process started")):
                decision = run_gate(directory, spec, "a" * 40)
                direct = run_check(directory, spec["checks"][0])
            self.assertEqual(decision["status"], "blocked")
            self.assertEqual(direct["status"], "blocked")
            self.assertEqual(decision["checks"][0]["status"], "blocked")
            self.assertEqual(decision["reason"], UNISOLATED_EVALUATOR_REASON)
            self.assertFalse(marker.exists(), "malicious evaluator executed or forged PASS")

    def test_all_checks_blocked_without_privileged_broker(self):
        spec = {"gate_id": "g", "contract": "c", "checks": [
            {"name": "apparently-passing", "command": [sys.executable, "-c", "pass"]},
            {"name": "apparently-failing", "command": [sys.executable, "-c", "raise SystemExit(1)"]},
        ]}
        with patch.object(subprocess, "run", side_effect=AssertionError("process started")):
            decision = run_gate(Path("/tmp"), spec, "b" * 40)
        self.assertEqual(decision["status"], "blocked")
        self.assertEqual([c["status"] for c in decision["checks"]], ["blocked", "blocked"])


class LedgerIdentity(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="orchestra-ledger-")
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name) / "home"
        self.identity = {
            "t3_thread_id": "thread-1", "receipt": "receipt-1",
            "task_id": "task-1", "phase": "review", "commit": "a" * 40,
            "worktree": "/tmp/checkout-1",
        }

    def test_record_without_worktree_rejected_without_ledger_mutation(self):
        result = record_launch(**{**self.identity, "worktree": None}, home=self.home)
        self.assertEqual(result["status"], "blocked")
        self.assertIn("worktree", result["reason"])
        self.assertFalse(receipt_path(self.home).exists())
        self.assertFalse(self.home.exists())

    def test_each_incomplete_identity_rejected_before_ledger_mutation(self):
        invalid = (
            ("t3_thread_id", "  "), ("receipt", "\nunsafe"),
            ("task_id", "bad\nvalue"), ("phase", " review "),
            ("commit", "f" * 39), ("worktree", "relative/path"),
            ("worktree", "/"), ("worktree", "/tmp/../tmp/checkout-1"),
            ("worktree", "/tmp/bad\npath"), ("worktree", "  "),
        )
        for field, replacement in invalid:
            with self.subTest(field=field, replacement=replacement):
                decision = record_launch(**{**self.identity, field: replacement}, home=self.home)
                self.assertEqual(decision["status"], "blocked")
                self.assertFalse(receipt_path(self.home).exists())

    def test_replay_same_identity_and_reject_changed_identity_without_append(self):
        first = record_launch(**self.identity, home=self.home)
        self.assertEqual(first["status"], "recorded")
        ledger = receipt_path(self.home)
        original = ledger.read_bytes()
        self.assertEqual(record_launch(**self.identity, home=self.home)["status"], "duplicate")
        self.assertEqual(reconcile(self.identity["t3_thread_id"], self.identity["receipt"],
                                   **{k: self.identity[k] for k in ("task_id", "phase", "commit", "worktree")},
                                   home=self.home)["status"], "replayed")
        for field, changed in (("task_id", "task-2"), ("phase", "implement"),
                               ("commit", "b" * 40), ("worktree", "/tmp/checkout-2"),
                               ("t3_thread_id", "thread-2")):
            with self.subTest(field=field):
                attempt = record_launch(**{**self.identity, field: changed}, home=self.home)
                self.assertEqual(attempt["status"], "blocked")
                self.assertEqual(ledger.read_bytes(), original)
        self.assertEqual(len(list_launches(home=self.home)), 1)

    def test_concurrent_same_identity_has_exactly_one_receipt(self):
        results = []
        threads = [threading.Thread(target=lambda: results.append(
            record_launch(**self.identity, home=self.home))) for _ in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sum(result["status"] == "recorded" for result in results), 1)
        self.assertEqual(sum(result["status"] == "duplicate" for result in results), 11)
        self.assertEqual(len(list_launches(home=self.home)), 1)


if __name__ == "__main__":
    unittest.main()
