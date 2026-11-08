from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from acceptance_evidence import build_payload, sign, verify_signature
from acceptance_gate import evaluate, load_gate_spec
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

    def _git(self, repo: Path, *args: str) -> str:
        return _git(repo, *args)

    def test_legitimate_signed_pass_blocks_without_broker(self) -> None:
        impl_repo = Path(tempfile.mkdtemp(prefix="orchestra-impl-"))
        _git(impl_repo, "init", "-q", "-b", "main")
        _git(impl_repo, "config", "user.name", "Pilot")
        _git(impl_repo, "config", "user.email", "pilot@example.invalid")
        (impl_repo / "ok.txt").write_text("good\n")
        _git(impl_repo, "add", "ok.txt")
        _git(impl_repo, "commit", "-q", "-m", "good")
        command = [sys.executable, "-c", "pass"]
        gate_path = impl_repo / ".orchestra-acceptance" / "gate.json"
        gate_path.parent.mkdir(parents=True, exist_ok=True)
        gate_path.write_text(
            json.dumps({"gate_id": "hidden-rubric", "contract": "the hidden evaluator must see a passing check", "checks": [{"name": "hidden", "command": command}]}, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        generate_keypair(self.home)
        payload = build_payload(impl_repo, files=["ok.txt"])
        envelope = sign(payload, Path(self.home) / "verifier_ed25519.pem")
        result = evaluate(impl_repo, envelope, gate_spec=json.loads(gate_path.read_text(encoding="utf-8")), home=self.home)
        self.assertEqual(result["status"], "blocked")
        self.assertIn("OS-principal isolation broker", result["reason"])

    def test_self_claimed_unsigned_pass_is_rejected(self) -> None:
        impl_repo = Path(tempfile.mkdtemp(prefix="orchestra-impl-"))
        _git(impl_repo, "init", "-q", "-b", "main")
        _git(impl_repo, "config", "user.name", "Pilot")
        _git(impl_repo, "config", "user.email", "pilot@example.invalid")
        (impl_repo / "ok.txt").write_text("good\n")
        _git(impl_repo, "add", "ok.txt")
        _git(impl_repo, "commit", "-q", "-m", "good")
        command = [sys.executable, "-c", "pass"]
        gate_path = impl_repo / ".orchestra-acceptance" / "gate.json"
        gate_path.parent.mkdir(parents=True, exist_ok=True)
        gate_path.write_text(
            json.dumps({"gate_id": "hidden-rubric", "contract": "the hidden evaluator must see a passing check", "checks": [{"name": "hidden", "command": command}]}, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        generate_keypair(self.home)
        payload = build_payload(impl_repo, files=["ok.txt"])
        envelope = {"payload": payload, "signature": "00" * 64, "algorithm": "ed25519"}
        result = evaluate(impl_repo, envelope, gate_spec=None, home=self.home)
        self.assertNotEqual(result["status"], "accepted")
        self.assertIn("signature", result["reason"])

    def test_false_pass_with_wrong_key_is_rejected(self) -> None:
        other = Path(tempfile.mkdtemp(prefix="orchestra-other-"))
        generate_keypair(other)
        impl_repo = Path(tempfile.mkdtemp(prefix="orchestra-impl-"))
        _git(impl_repo, "init", "-q", "-b", "main")
        _git(impl_repo, "config", "user.name", "Pilot")
        _git(impl_repo, "config", "user.email", "pilot@example.invalid")
        (impl_repo / "ok.txt").write_text("good\n")
        _git(impl_repo, "add", "ok.txt")
        _git(impl_repo, "commit", "-q", "-m", "good")
        command = [sys.executable, "-c", "pass"]
        gate_path = impl_repo / ".orchestra-acceptance" / "gate.json"
        gate_path.parent.mkdir(parents=True, exist_ok=True)
        gate_path.write_text(
            json.dumps({"gate_id": "hidden-rubric", "contract": "the hidden evaluator must see a passing check", "checks": [{"name": "hidden", "command": command}]}, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        generate_keypair(self.home)
        payload = build_payload(impl_repo, files=["ok.txt"])
        envelope = sign(payload, Path(other) / "verifier_ed25519.pem")
        result = evaluate(impl_repo, envelope, gate_spec=json.loads(gate_path.read_text(encoding="utf-8")), home=self.home)
        self.assertNotEqual(result["status"], "accepted")

    def test_failing_implementation_not_executed_without_broker(self) -> None:
        impl_repo = Path(tempfile.mkdtemp(prefix="orchestra-impl-"))
        _git(impl_repo, "init", "-q", "-b", "main")
        _git(impl_repo, "config", "user.name", "Pilot")
        _git(impl_repo, "config", "user.email", "pilot@example.invalid")
        (impl_repo / "ok.txt").write_text("good\n")
        _git(impl_repo, "add", "ok.txt")
        _git(impl_repo, "commit", "-q", "-m", "good")
        gate_path = impl_repo / ".orchestra-acceptance" / "gate.json"
        gate_path.parent.mkdir(parents=True, exist_ok=True)
        gate_path.write_text(
            json.dumps({"gate_id": "hidden-rubric", "contract": "deliberately wrong implementation", "checks": [{"name": "hidden", "command": [sys.executable, "-c", "raise SystemExit(1)"]}]}, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        generate_keypair(self.home)
        payload = build_payload(impl_repo, files=["ok.txt"])
        envelope = sign(payload, Path(self.home) / "verifier_ed25519.pem")
        result = evaluate(impl_repo, envelope, gate_spec=json.loads(gate_path.read_text(encoding="utf-8")), home=self.home)
        self.assertEqual(result["status"], "blocked")
        self.assertIn("OS-principal isolation broker", result["reason"])

    def test_tampered_evidence_after_signing_is_rejected(self) -> None:
        impl_repo = Path(tempfile.mkdtemp(prefix="orchestra-impl-"))
        _git(impl_repo, "init", "-q", "-b", "main")
        _git(impl_repo, "config", "user.name", "Pilot")
        _git(impl_repo, "config", "user.email", "pilot@example.invalid")
        (impl_repo / "ok.txt").write_text("good\n")
        _git(impl_repo, "add", "ok.txt")
        _git(impl_repo, "commit", "-q", "-m", "good")
        gate_path = impl_repo / ".orchestra-acceptance" / "gate.json"
        gate_path.parent.mkdir(parents=True, exist_ok=True)
        gate_path.write_text(
            json.dumps({"gate_id": "hidden-rubric", "contract": "deliberately wrong implementation", "checks": [{"name": "hidden", "command": [sys.executable, "-c", "raise SystemExit(1)"]}]}, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        generate_keypair(self.home)
        payload = build_payload(impl_repo, files=["ok.txt"])
        envelope = sign(payload, Path(self.home) / "verifier_ed25519.pem")

        (impl_repo / "ok.txt").write_text("tampered\n", encoding="utf-8")
        _git(impl_repo, "add", "ok.txt")
        _git(impl_repo, "commit", "-q", "-m", "tamper")

        result = evaluate(impl_repo, envelope, gate_spec=json.loads(gate_path.read_text(encoding="utf-8")), home=self.home)
        self.assertNotEqual(result["status"], "accepted")
        self.assertIn("commit", result["reason"])


if __name__ == "__main__":
    unittest.main()
