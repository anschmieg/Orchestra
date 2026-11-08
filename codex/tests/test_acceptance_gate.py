from __future__ import annotations

import json
import os
import sys
import subprocess
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from acceptance_evidence import build_payload, sign, write_envelope
from acceptance_gate import evaluate, load_gate_spec, run_gate, validate_gate_spec
from acceptance_keyring import generate_keypair


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=False
    )
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    return result.stdout.strip()


class GateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(prefix="orchestra-gate-"))
        self.repo = Path(tempfile.mkdtemp(prefix="orchestra-gaterepo-"))
        _git(self.repo, "init", "-q", "-b", "main")
        _git(self.repo, "config", "user.name", "Test")
        _git(self.repo, "config", "user.email", "test@example.invalid")
        (self.repo / "ok.txt").write_text("good\n", encoding="utf-8")
        _git(self.repo, "add", "ok.txt")
        _git(self.repo, "commit", "-q", "-m", "good")
        self.good_commit = _git(self.repo, "rev-parse", "HEAD")
        self.spec_path = self.repo / ".orchestra-acceptance" / "gate.json"
        generate_keypair(self.home)

    def _write_gate(self, repo: Path, command: list[str]) -> Path:
        path = repo / ".orchestra-acceptance" / "gate.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {"gate_id": "g1", "contract": "c1", "checks": [{"name": "c", "command": command}]},
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        return path

    def test_valid_envelope_blocks_without_broker(self) -> None:
        command = [sys.executable, "-c", "pass"]
        self._write_gate(self.repo, command)
        spec = load_gate_spec(self.spec_path)
        payload = build_payload(self.repo, files=["ok.txt"])
        envelope = sign(payload, Path(self.home) / "verifier_ed25519.pem")
        result = evaluate(self.repo, envelope, gate_spec=spec, home=self.home)
        self.assertEqual(result["status"], "blocked")
        self.assertIn("OS-principal isolation broker", result["reason"])

    def test_unsigned_envelope_rejects(self) -> None:
        command = [sys.executable, "-c", "pass"]
        self._write_gate(self.repo, command)
        payload = build_payload(self.repo, files=["ok.txt"])
        envelope = {"payload": payload, "signature": "00" * 64, "algorithm": "ed25519"}
        result = evaluate(self.repo, envelope, gate_spec=None, home=self.home)
        self.assertEqual(result["status"], "blocked")
        self.assertIn("signature", result["reason"])

    def test_missing_gate_spec_blocks(self) -> None:
        command = [sys.executable, "-c", "pass"]
        self._write_gate(self.repo, command)
        payload = build_payload(self.repo, files=["ok.txt"])
        envelope = sign(payload, Path(self.home) / "verifier_ed25519.pem")
        result = evaluate(self.repo, envelope, gate_spec=None, home=self.home)
        self.assertEqual(result["status"], "blocked")
        self.assertIn("gate spec", result["reason"])

    def test_wrong_key_rejects(self) -> None:
        other = Path(tempfile.mkdtemp(prefix="orchestra-other-"))
        generate_keypair(other)
        command = [sys.executable, "-c", "pass"]
        self._write_gate(self.repo, command)
        spec = load_gate_spec(self.spec_path)
        payload = build_payload(self.repo, files=["ok.txt"])
        envelope = sign(payload, Path(other) / "verifier_ed25519.pem")
        result = evaluate(self.repo, envelope, gate_spec=spec, home=self.home)
        self.assertEqual(result["status"], "blocked")

    def test_failing_check_not_executed_without_broker(self) -> None:
        command = [sys.executable, "-c", "raise SystemExit(7)"]
        self._write_gate(self.repo, command)
        spec = load_gate_spec(self.spec_path)
        payload = build_payload(self.repo, files=["ok.txt"])
        envelope = sign(payload, Path(self.home) / "verifier_ed25519.pem")
        result = evaluate(self.repo, envelope, gate_spec=spec, home=self.home)
        self.assertEqual(result["status"], "blocked")
        self.assertIn("OS-principal isolation broker", result["reason"])

    def test_missing_contract_blocks(self) -> None:
        payload = build_payload(self.repo, files=["ok.txt"])
        envelope = sign(payload, Path(self.home) / "verifier_ed25519.pem")
        result = evaluate(self.repo, envelope, gate_spec=None, home=self.home)
        self.assertEqual(result["status"], "blocked")
        self.assertIn("gate spec", result["reason"])

    def test_tree_mismatch_blocks(self) -> None:
        command = [sys.executable, "-c", "pass"]
        self._write_gate(self.repo, command)
        spec = load_gate_spec(self.spec_path)
        payload = build_payload(self.repo, files=["ok.txt"])
        envelope = sign(payload, Path(self.home) / "verifier_ed25519.pem")
        (self.repo / "other.txt").write_text("x\n", encoding="utf-8")
        _git(self.repo, "add", "other.txt")
        _git(self.repo, "commit", "-q", "-m", "other")
        result = evaluate(self.repo, envelope, gate_spec=spec, home=self.home)
        self.assertEqual(result["status"], "blocked")
        self.assertIn("commit", result["reason"])

    def test_validate_gate_spec_rejects_bad_shape(self) -> None:
        self.assertIsNotNone(validate_gate_spec({"gate_id": "x", "contract": "y", "checks": []}))
        self.assertIsNotNone(validate_gate_spec({"gate_id": "x", "contract": "y"}))
        self.assertIsNotNone(
            validate_gate_spec({"gate_id": "x", "contract": "y", "checks": [{"name": "c", "command": "pass"}]})
        )
        self.assertIsNone(
            validate_gate_spec({"gate_id": "x", "contract": "y", "checks": [{"name": "c", "command": ["python3", "-c", "pass"]}]}))
        self.assertIsNone(load_gate_spec(self.repo))

    def test_tampered_gate_json_cannot_execute_without_broker(self) -> None:
        command = [sys.executable, "-c", "raise SystemExit(1)"]
        self._write_gate(self.repo, command)
        spec = load_gate_spec(self.spec_path)
        payload = build_payload(self.repo, files=["ok.txt"])
        envelope = sign(payload, Path(self.home) / "verifier_ed25519.pem")

        tampered = {"gate_id": "g1", "contract": "tampered", "checks": [{"name": "c", "command": [sys.executable, "-c", "pass"]}]}
        self.spec_path.write_text(json.dumps(tampered, sort_keys=True) + "\n", encoding="utf-8")

        result = evaluate(self.repo, envelope, gate_spec=spec, home=self.home)
        self.assertEqual(result["status"], "blocked")
        self.assertIn("OS-principal isolation broker", result["reason"])


if __name__ == "__main__":
    unittest.main()
