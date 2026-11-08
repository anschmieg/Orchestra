from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from acceptance_evidence import build_payload, sign, verify
from acceptance_gate import evaluate, load_gate_spec
from acceptance_keyring import generate_keypair


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=False
    )
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    return result.stdout.strip()


class SecurityRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(prefix="orchestra-sec-"))

    def test_signed_commit_mismatch_rejected(self):
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
            json.dumps({"gate_id": "g1", "contract": "test", "checks": [{"name": "c", "command": command}]}, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        generate_keypair(self.home)
        payload = build_payload(impl_repo, files=["ok.txt"])
        envelope = sign(payload, Path(self.home) / "verifier_ed25519.pem")
        (impl_repo / "other.txt").write_text("x\n")
        _git(impl_repo, "add", "other.txt")
        _git(impl_repo, "commit", "-q", "-m", "other")
        result = evaluate(impl_repo, envelope, gate_spec=json.loads(gate_path.read_text(encoding="utf-8")), home=self.home)
        self.assertEqual(result["status"], "blocked")
        self.assertIn("signed commit does not match checkout HEAD commit", result["reason"])

    def test_expected_commit_mismatch_rejected(self):
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
            json.dumps({"gate_id": "g1", "contract": "test", "checks": [{"name": "c", "command": command}]}, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        generate_keypair(self.home)
        payload = build_payload(impl_repo, files=["ok.txt"])
        envelope = sign(payload, Path(self.home) / "verifier_ed25519.pem")
        wrong_commit = "a" * 40
        result = evaluate(impl_repo, envelope, gate_spec=json.loads(gate_path.read_text(encoding="utf-8")), home=self.home, expected_commit=wrong_commit)
        self.assertEqual(result["status"], "blocked")
        self.assertIn("signed commit does not match expected commit", result["reason"])

    def test_spec_from_implementer_path_rejected(self):
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
            json.dumps({"gate_id": "impl-controlled", "contract": "test", "checks": [{"name": "c", "command": command}]}, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        generate_keypair(self.home)
        payload = build_payload(impl_repo, files=["ok.txt"])
        envelope = sign(payload, Path(self.home) / "verifier_ed25519.pem")
        spec = load_gate_spec(gate_path)
        result = evaluate(impl_repo, envelope, gate_spec=spec, home=self.home)
        # CLI now blocks impl-controlled specs, but gate still evaluates
        self.assertEqual(result["status"], "blocked")
        self.assertIn("OS-principal isolation broker", result["reason"])

    def test_worktree_mutation_after_signing_immutable_checkout(self):
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
            json.dumps({"gate_id": "g1", "contract": "test", "checks": [{"name": "c", "command": command}]}, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        generate_keypair(self.home)
        payload = build_payload(impl_repo, files=["ok.txt"])
        envelope = sign(payload, Path(self.home) / "verifier_ed25519.pem")
        (impl_repo / "ok.txt").write_text("tampered\n")
        spec = load_gate_spec(gate_path)
        result = evaluate(impl_repo, envelope, gate_spec=spec, home=self.home)
        self.assertEqual(result["status"], "blocked")
        self.assertIn("OS-principal isolation broker", result["reason"])

    def test_worktree_checks_rejected_when_mutation_breaks_check(self):
        impl_repo = Path(tempfile.mkdtemp(prefix="orchestra-impl-"))
        _git(impl_repo, "init", "-q", "-b", "main")
        _git(impl_repo, "config", "user.name", "Pilot")
        _git(impl_repo, "config", "user.email", "pilot@example.invalid")
        (impl_repo / "ok.txt").write_text("good\n")
        _git(impl_repo, "add", "ok.txt")
        _git(impl_repo, "commit", "-q", "-m", "good")
        check_script = "import sys\ncontent = open('ok.txt').read().strip()\nif content != 'good':\n    sys.exit(1)\n"
        gate_path = impl_repo / ".orchestra-acceptance" / "gate.json"
        gate_path.parent.mkdir(parents=True, exist_ok=True)
        gate_path.write_text(
            json.dumps({"gate_id": "g1", "contract": "test", "checks": [{"name": "c", "command": [sys.executable, "-c", check_script]}]}, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        generate_keypair(self.home)
        payload = build_payload(impl_repo, files=["ok.txt"])
        envelope = sign(payload, Path(self.home) / "verifier_ed25519.pem")
        (impl_repo / "ok.txt").write_text("tampered\n")
        spec = load_gate_spec(gate_path)
        result = evaluate(impl_repo, envelope, gate_spec=spec, home=self.home)
        self.assertEqual(result["status"], "blocked")
        self.assertIn("OS-principal isolation broker", result["reason"])

    def test_immutable_checkout_detects_committed_tampering(self):
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
            json.dumps({"gate_id": "g1", "contract": "test", "checks": [{"name": "c", "command": command}]}, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        generate_keypair(self.home)
        payload = build_payload(impl_repo, files=["ok.txt"])
        envelope = sign(payload, Path(self.home) / "verifier_ed25519.pem")
        (impl_repo / "ok.txt").write_text("tampered\n")
        _git(impl_repo, "add", "ok.txt")
        _git(impl_repo, "commit", "-q", "-m", "tamper")
        spec = load_gate_spec(gate_path)
        result = evaluate(impl_repo, envelope, gate_spec=spec, home=self.home)
        self.assertEqual(result["status"], "blocked")
        self.assertIn("commit", result["reason"])

    def test_verifier_provided_spec_path_immutable(self):
        impl_repo = Path(tempfile.mkdtemp(prefix="orchestra-impl-"))
        _git(impl_repo, "init", "-q", "-b", "main")
        _git(impl_repo, "config", "user.name", "Pilot")
        _git(impl_repo, "config", "user.email", "pilot@example.invalid")
        (impl_repo / "ok.txt").write_text("good\n")
        _git(impl_repo, "add", "ok.txt")
        _git(impl_repo, "commit", "-q", "-m", "good")
        command = [sys.executable, "-c", "raise SystemExit(1)"]
        gate_path = impl_repo / ".orchestra-acceptance" / "gate.json"
        gate_path.parent.mkdir(parents=True, exist_ok=True)
        gate_path.write_text(
            json.dumps({"gate_id": "g1", "contract": "test", "checks": [{"name": "c", "command": command}]}, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        generate_keypair(self.home)
        payload = build_payload(impl_repo, files=["ok.txt"])
        envelope = sign(payload, Path(self.home) / "verifier_ed25519.pem")
        spec = load_gate_spec(gate_path)
        result = evaluate(impl_repo, envelope, gate_spec=spec, home=self.home)
        self.assertEqual(result["status"], "blocked")
        self.assertIn("OS-principal isolation broker", result["reason"])


if __name__ == "__main__":
    unittest.main()
