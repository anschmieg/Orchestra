from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from acceptance_evidence import build_payload, sign, write_envelope
from acceptance_keyring import generate_keypair


CLI = Path(__file__).resolve().parent / ".." / "scripts" / "acceptance_cli.py"
SCRIPTS = Path(__file__).resolve().parent / ".." / "scripts"


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=False
    )
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    return result.stdout.strip()


class OSPrincipalAdversarialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="orchestra-os-principal-"))
        self.impl_repo = self.tmp / "impl"
        self.impl_repo.mkdir()
        _git(self.impl_repo, "init", "-q", "-b", "main")
        _git(self.impl_repo, "config", "user.name", "Impl")
        _git(self.impl_repo, "config", "user.email", "impl@test")
        (self.impl_repo / "ok.txt").write_text("good\n")
        _git(self.impl_repo, "add", "ok.txt")
        _git(self.impl_repo, "commit", "-q", "-m", "good")
        self.commit = _git(self.impl_repo, "rev-parse", "HEAD")

    def test_attacker_valid_key_valid_spec_blocked_by_uid(self):
        attacker_home = self.tmp / "attacker"
        attacker_home.mkdir()
        generate_keypair(attacker_home)
        (attacker_home / "grants.json").write_text(
            json.dumps({"grants": ["verify_evidence"]}),
            encoding="utf-8",
        )
        attacker_spec = self.tmp / "attacker-spec.json"
        attacker_spec.write_text(
            json.dumps({"gate_id": "legitimate-gate", "contract": "real", "checks": [
                {"name": "c", "command": [sys.executable, "-c", "pass"]}]}),
            encoding="utf-8",
        )
        attacker_payload = build_payload(self.impl_repo, files=["ok.txt"])
        attacker_envelope = sign(attacker_payload, attacker_home / "verifier_ed25519.pem")
        evidence_path = self.tmp / "evidence.json"
        write_envelope(evidence_path, attacker_envelope)
        report_path = self.tmp / "report.json"
        proc = subprocess.run(
            [sys.executable, str(CLI), "approve",
             "--repo", str(self.impl_repo),
             "--evidence", str(evidence_path),
             "--spec", str(attacker_spec),
             "--home", str(attacker_home),
             "--report", str(self.tmp / "report.json")],
            capture_output=True, text=True,
        )
        self.assertNotEqual(proc.returncode, 0)
        if proc.stdout.strip():
            result = json.loads(proc.stdout)
            self.assertEqual(result["status"], "blocked")
            self.assertIn("verifier UID", result["reason"])

    def test_attacker_cannot_bypass_with_real_verifier_file_but_wrong_uid(self):
        attacker_spec = self.tmp / "attacker-spec.json"
        attacker_spec.write_text(
            json.dumps({"gate_id": "legitimate-gate", "contract": "real", "checks": [
                {"name": "c", "command": [sys.executable, "-c", "pass"]}]}),
            encoding="utf-8",
        )
        attacker_home = self.tmp / "attacker"
        attacker_home.mkdir()
        generate_keypair(attacker_home)
        (attacker_home / "grants.json").write_text(
            json.dumps({"grants": ["verify_evidence"]}),
            encoding="utf-8",
        )
        attacker_payload = build_payload(self.impl_repo, files=["ok.txt"])
        attacker_envelope = sign(attacker_payload, attacker_home / "verifier_ed25519.pem")
        evidence_path = self.tmp / "evidence.json"
        write_envelope(evidence_path, attacker_envelope)
        report_path = self.tmp / "report.json"
        proc = subprocess.run(
            [sys.executable, str(CLI), "approve",
             "--repo", str(self.impl_repo),
             "--evidence", str(evidence_path),
             "--spec", str(attacker_spec),
             "--home", str(attacker_home),
             "--report", str(self.tmp / "report.json")],
            capture_output=True, text=True,
        )
        self.assertNotEqual(proc.returncode, 0)
        if proc.stdout.strip():
            result = json.loads(proc.stdout)
            self.assertEqual(result["status"], "blocked")
            self.assertIn("verifier UID", result["reason"])


if __name__ == "__main__":
    unittest.main()
