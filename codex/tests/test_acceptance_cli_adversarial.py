from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import acceptance_cli

CLI = Path(__file__).resolve().parent / ".." / "scripts" / "acceptance_cli.py"
SCRIPTS = Path(__file__).resolve().parent / ".." / "scripts"


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=False
    )
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    return result.stdout.strip()


class CLIAdversarialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="orchestra-cli-"))


    def test_start_records_receipt_with_valid_grant(self):
        repo = self.tmp / "impl"
        repo.mkdir()
        env = {**os.environ, "ORCHESTRA_ACCEPTANCE_GRANT": "record_launch"}
        argv = [
            sys.executable, str(CLI), "--home", str(self.tmp / "state"), "start",
            "--repo", str(repo), "--t3-thread-id", "thread-1",
            "--receipt", "receipt-1", "--task-id", "task-1", "--phase", "implement",
            "--commit", "a" * 40,
        ]
        first = subprocess.run(argv, capture_output=True, text=True, env=env)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertEqual(json.loads(first.stdout)["status"], "recorded")
        replay = subprocess.run(argv, capture_output=True, text=True, env=env)
        self.assertEqual(replay.returncode, 1, replay.stdout + replay.stderr)
        self.assertEqual(json.loads(replay.stdout)["status"], "duplicate")

    def test_approve_uses_policy_api_without_home_keyword(self):
        repo = self.tmp / "impl"
        repo.mkdir()
        verifier = self.tmp / "verifier"
        verifier.mkdir()
        spec = verifier / "gate.json"
        spec.write_text("{}", encoding="utf-8")
        evidence = self.tmp / "evidence.json"
        evidence.write_text("{}", encoding="utf-8")
        args = argparse.Namespace(
            repo=repo, spec=spec, evidence=evidence, report=verifier / "report.json"
        )
        with (
            patch.dict(os.environ, {"ORCHESTRA_ACCEPTANCE_GRANT": "verify_evidence"}),
            patch.object(acceptance_cli, "VERIFIER_HOME", verifier),
            patch.object(acceptance_cli, "_verifier_principal_check", return_value={"status": "ok"}),
            patch.object(acceptance_cli, "_run", return_value=(0, '{"status":"accepted"}\n', "")),
        ):
            self.assertEqual(acceptance_cli.cmd_approve(args), 0)

    def test_attacker_spec_cannot_manufacture_accepted(self):
        impl_repo = self.tmp / "impl"
        impl_repo.mkdir()
        _git(impl_repo, "init", "-q", "-b", "main")
        _git(impl_repo, "config", "user.name", "Pilot")
        _git(impl_repo, "config", "user.email", "pilot@example.invalid")
        (impl_repo / "ok.txt").write_text("good\n")
        _git(impl_repo, "add", "ok.txt")
        _git(impl_repo, "commit", "-q", "-m", "good")
        commit = _git(impl_repo, "rev-parse", "HEAD")

        verifier_home = self.tmp / "verifier"
        verifier_home.mkdir()
        (verifier_home / "grants.json").write_text(
            json.dumps({"grants": ["manage_keyring", "verify_evidence", "record_launch"]}),
            encoding="utf-8",
        )
        subprocess.run(
            [sys.executable, str(SCRIPTS / "acceptance_cli.py"), "--home", str(verifier_home), "enroll"],
            capture_output=True, check=True,
        )

        attacker_spec = self.tmp / "attacker-spec.json"
        attacker_spec.write_text(
            json.dumps({"gate_id": "impl-controlled", "contract": "fake", "checks": [
                {"name": "pass", "command": [sys.executable, "-c", "pass"]}]}),
            encoding="utf-8",
        )

        evidence_path = self.tmp / "evidence.json"
        evidence_path.write_text(
            json.dumps({"payload": {"commit": commit, "tree": _git(impl_repo, "rev-parse", "HEAD^{tree}"),
                                   "files": {}}, "signature": "00" * 64, "algorithm": "ed25519"}),
            encoding="utf-8",
        )

        report_path = self.tmp / "report.json"

        proc = subprocess.run(
            [sys.executable, str(CLI), "approve",
             "--repo", str(impl_repo),
             "--evidence", str(evidence_path),
             "--spec", str(attacker_spec),
             "--home", str(verifier_home),
             "--report", str(report_path)],
            capture_output=True, text=True,
        )
        self.assertNotEqual(proc.returncode, 0)
        if proc.stdout.strip():
            result = json.loads(proc.stdout)
            self.assertNotEqual(result["status"], "accepted")

    def test_missing_home_keyring_rejected(self):
        impl_repo = self.tmp / "impl"
        impl_repo.mkdir()
        _git(impl_repo, "init", "-q", "-b", "main")
        _git(impl_repo, "config", "user.name", "Pilot")
        _git(impl_repo, "config", "user.email", "pilot@example.invalid")
        (impl_repo / "ok.txt").write_text("good\n")
        _git(impl_repo, "add", "ok.txt")
        _git(impl_repo, "commit", "-q", "-m", "good")
        commit = _git(impl_repo, "rev-parse", "HEAD")

        empty_home = self.tmp / "empty-home"
        empty_home.mkdir()
        spec = self.tmp / "spec.json"
        spec.write_text(
            json.dumps({"gate_id": "g1", "contract": "test", "checks": [
                {"name": "pass", "command": [sys.executable, "-c", "pass"]}]}),
            encoding="utf-8",
        )
        evidence_path = self.tmp / "evidence.json"
        evidence_path.write_text(
            json.dumps({"payload": {"commit": commit, "tree": _git(impl_repo, "rev-parse", "HEAD^{tree}"),
                                   "files": {}}, "signature": "00" * 64, "algorithm": "ed25519"}),
            encoding="utf-8",
        )
        report_path = self.tmp / "report.json"

        proc = subprocess.run(
            [sys.executable, str(CLI), "approve",
             "--repo", str(impl_repo),
             "--evidence", str(evidence_path),
             "--spec", str(spec),
             "--home", str(empty_home),
             "--report", str(report_path)],
            capture_output=True, text=True,
        )
        self.assertNotEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
