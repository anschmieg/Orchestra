#!/usr/bin/env python3

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from acceptance_evidence import (
    build_payload,
    commit_sha,
    git,
    load_envelope,
    sign,
    tree_sha,
    verify,
    write_envelope,
)
from acceptance_keyring import generate_keypair, load_verify_key


class EvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(prefix="orchestra-acceptance-"))
        self.repo = Path(tempfile.mkdtemp(prefix="orchestra-repo-"))
        self.git(self.repo, "init", "-q", "-b", "main")
        self.git(self.repo, "config", "user.name", "Test")
        self.git(self.repo, "config", "user.email", "test@example.invalid")
        (self.repo / "file.txt").write_text("hello\n", encoding="utf-8")
        self.git(self.repo, "add", "file.txt")
        self.git(self.repo, "commit", "-q", "-m", "init")
        self.commit = commit_sha(self.repo)

    def git(self, repo: Path, *args: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(repo), *args], capture_output=True, text=True, check=False
        )
        if result.returncode:
            self.fail(result.stdout + result.stderr)
        return result.stdout.strip()

    def test_payload_ties_commit_tree_and_files(self) -> None:
        payload = build_payload(self.repo, files=["file.txt"], checks=[{"name": "c", "status": "passed"}])
        self.assertEqual(payload["commit"], self.commit)
        self.assertEqual(payload["tree"], tree_sha(self.repo))
        self.assertIn("file.txt", payload["files"])
        self.assertEqual(len(payload["files"]["file.txt"]), 64)

    def test_rejects_non_sha_commit(self) -> None:
        with self.assertRaises(RuntimeError):
            build_payload(self.repo, commit="HEAD")

    def test_signed_envelope_verifies(self) -> None:
        generate_keypair(self.home)
        payload = build_payload(self.repo, files=["file.txt"])
        envelope = sign(payload, Path(self.home) / "verifier_ed25519.pem")
        result = verify(envelope, home=self.home)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["commit"], self.commit)

    def test_envelope_round_trips_through_disk(self) -> None:
        generate_keypair(self.home)
        payload = build_payload(self.repo, files=["file.txt"])
        envelope = sign(payload, Path(self.home) / "verifier_ed25519.pem")
        path = Path(tempfile.mktemp(suffix=".json"))
        write_envelope(path, envelope)
        loaded = load_envelope(path)
        self.assertEqual(verify(loaded, home=self.home)["status"], "ok")
        path.unlink()

    def test_wrong_key_rejects_envelope(self) -> None:
        other = Path(tempfile.mkdtemp(prefix="orchestra-other-"))
        generate_keypair(self.home)
        generate_keypair(other)
        payload = build_payload(self.repo, files=["file.txt"])
        envelope = sign(payload, Path(self.home) / "verifier_ed25519.pem")
        verify_key = load_verify_key((Path(other) / "verifier_ed25519.pub").read_bytes())
        from acceptance_evidence import verify_signature
        self.assertFalse(verify_signature(envelope["payload"], envelope["signature"], verify_key))


if __name__ == "__main__":
    unittest.main()
