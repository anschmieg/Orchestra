#!/usr/bin/env python3

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import json
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from acceptance_evidence import build_payload, sign
from acceptance_gate import evaluate
from acceptance_keyring import generate_keypair


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=False
    )
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    return result.stdout.strip()


class AdversarialPilotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(prefix="orchestra-pilot-"))
        self.repo = Path(tempfile.mkdtemp(prefix="orchestra-pilotrepo-"))
        _git(self.repo, "init", "-q", "-b", "main")
        _git(self.repo, "config", "user.name", "Pilot")
        _git(self.repo, "config", "user.email", "pilot@example.invalid")
        (self.repo / "ok.txt").write_text("good\n", encoding="utf-8")
        _git(self.repo, "add", "ok.txt")
        _git(self.repo, "commit", "-q", "-m", "good")
        generate_keypair(self.home)
        gate = self.repo / ".orchestra-acceptance" / "gate.json"
        gate.parent.mkdir(parents=True, exist_ok=True)
        gate.write_text(
            json.dumps(
                {
                    "gate_id": "hidden-rubric",
                    "contract": "the hidden evaluator must see a passing check",
                    "checks": [
                        {"name": "hidden", "command": [sys.executable, "-c", "pass"]}
                    ],
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    def _signed(self) -> dict:
        payload = build_payload(self.repo, files=["ok.txt"])
        return sign(payload, Path(self.home) / "verifier_ed25519.pem")

    def test_legitimate_signed_pass_is_accepted(self) -> None:
        result = evaluate(self.repo, self._signed(), home=self.home)
        self.assertEqual(result["status"], "accepted")

    def test_self_claimed_unsigned_pass_is_rejected(self) -> None:
        payload = build_payload(self.repo, files=["ok.txt"])
        envelope = {"payload": payload, "signature": "00" * 64, "algorithm": "ed25519"}
        result = evaluate(self.repo, envelope, home=self.home)
        self.assertNotEqual(result["status"], "accepted")
        self.assertIn("signature", result["reason"])

    def test_false_pass_with_wrong_key_is_rejected(self) -> None:
        other = Path(tempfile.mkdtemp(prefix="orchestra-other-"))
        generate_keypair(other)
        payload = build_payload(self.repo, files=["ok.txt"])
        envelope = sign(payload, Path(other) / "verifier_ed25519.pem")
        result = evaluate(self.repo, envelope, home=self.home)
        self.assertNotEqual(result["status"], "accepted")

    def test_deliberately_failing_implementation_is_rejected(self) -> None:
        gate = self.repo / ".orchestra-acceptance" / "gate.json"
        gate.write_text(
            json.dumps(
                {
                    "gate_id": "hidden-rubric",
                    "contract": "deliberately wrong implementation",
                    "checks": [
                        {"name": "hidden", "command": [sys.executable, "-c", "raise SystemExit(1)"]}
                    ],
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        result = evaluate(self.repo, self._signed(), home=self.home)
        self.assertEqual(result["status"], "rejected")

    def test_tampered_evidence_after_signing_is_rejected(self) -> None:
        envelope = self._signed()
        (self.repo / "ok.txt").write_text("tampered\n", encoding="utf-8")
        _git(self.repo, "add", "ok.txt")
        _git(self.repo, "commit", "-q", "-m", "tamper")
        result = evaluate(self.repo, envelope, home=self.home)
        self.assertNotEqual(result["status"], "accepted")
        self.assertIn("tree", result["reason"])


if __name__ == "__main__":
    unittest.main()
