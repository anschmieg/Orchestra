from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from acceptance_keyring import default_home

CLI = Path(__file__).resolve().parent / ".." / "scripts" / "acceptance_cli.py"
HOME = default_home()


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

    def test_attacker_spec_cannot_manufacture_accepted(self):
        """Attacker-controlled spec with trivial pass check cannot get accepted via CLI."""
        impl_repo = self.tmp / "impl"
        impl_repo.mkdir()
        _git(impl_repo, "init", "-q", "-b", "main")
        _git(impl_repo, "config", "user.name", "Pilot")
        _git(impl_repo, "config", "user.email", "pilot@example.invalid")
        (impl_repo / "ok.txt").write_text("good\n")
        _git(impl_repo, "add", "ok.txt")
        _git(impl_repo, "commit", "-q", "-m", "good")
        commit = _git(impl_repo, "rev-parse", "HEAD")

        # Verifier keypair in a separate home
        verifier_home = self.tmp / "verifier"
        subprocess.run([sys.executable, str(Path(__file__).resolve().parent / ".." / "scripts" / "acceptance_keyring.py") if False else sys.executable, "-c",
            f"import sys; sys.path.insert(0, '{Path(__file__).resolve().parent / '..' / 'scripts'}'); "
            f"from acceptance_keyring import generate_keypair; import pathlib; "
            f"generate_keypair(pathlib.Path('{verifier_home}'))"],
            capture_output=True, check=True)

        # Attacker-controlled spec: trivial pass check
        attacker_spec = self.tmp / "attacker-spec.json"
        attacker_spec.write_text(
            json.dumps({"gate_id": "impl-controlled", "contract": "fake", "checks": [
                {"name": "pass", "command": [sys.executable, "-c", "pass"]}]}),
            encoding="utf-8",
        )

        # Attacker creates fake evidence signed with attacker's own key (self-authorized home)
        evidence_path = self.tmp / "evidence.json"
        evidence_path.write_text(
            json.dumps({"payload": {"commit": commit, "tree": _git(impl_repo, "rev-parse", "HEAD^{tree}"),
                                   "files": {}}, "signature": "00" * 64, "algorithm": "ed25519"}),
            encoding="utf-8",
        )

        report_path = self.tmp / "report.json"

        # Run CLI approve with attacker-controlled spec/home/report
        proc = subprocess.run(
            [sys.executable, str(CLI), "approve",
             "--repo", str(impl_repo),
             "--evidence", str(evidence_path),
             "--spec", str(attacker_spec),
             "--home", str(verifier_home),
             "--report", str(report_path)],
            capture_output=True, text=True,
        )
        result = json.loads(proc.stdout)
        self.assertEqual(result["status"], "blocked")

    def test_missing_home_keyring_rejected(self):
        """CLI approve fails when home lacks valid keyring."""
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
        attacker_spec = self.tmp / "spec.json"
        attacker_spec.write_text(
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
             "--spec", str(attacker_spec),
             "--home", str(empty_home),
             "--report", str(report_path)],
            capture_output=True, text=True,
        )
        result = json.loads(proc.stdout)
        self.assertIn(result["status"], ("blocked",))


if __name__ == "__main__":
    unittest.main()
