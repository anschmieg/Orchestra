#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from acceptance_keyring import (
    default_home,
    generate_keypair,
    load_keyring,
    load_signing_key,
    load_verify_key,
    save_keyring,
    sign_payload,
    verify_against_any_trusted,
    verify_signature,
)


class KeyringTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home = Path(tempfile.mkdtemp(prefix="orchestra-acceptance-"))
        self.addCleanup(lambda: None)

    def test_generate_keypair_creates_files_and_ring(self) -> None:
        result = generate_keypair(self.home)
        self.assertTrue(Path(result["private_key"]).is_file())
        self.assertTrue(Path(result["public_key"]).is_file())
        self.assertTrue(Path(result["keyring"]).is_file())
        ring = load_keyring(self.home)
        self.assertEqual(ring["verifier_public_key"], result["verifier_public_key"])
        self.assertEqual(ring["trusted"], [])

    def test_sign_and_verify_round_trip(self) -> None:
        generate_keypair(self.home)
        key = load_signing_key(Path(self.home) / "verifier_ed25519.pem")
        payload = {"commit": "a" * 40, "tree": "b" * 40}
        signature = sign_payload(payload, key)
        verify_key = load_verify_key((Path(self.home) / "verifier_ed25519.pub").read_bytes())
        self.assertTrue(verify_signature(payload, signature, verify_key))

    def test_tampered_payload_rejects(self) -> None:
        generate_keypair(self.home)
        key = load_signing_key(Path(self.home) / "verifier_ed25519.pem")
        payload = {"commit": "a" * 40}
        signature = sign_payload(payload, key)
        payload["commit"] = "b" * 40
        verify_key = load_verify_key((Path(self.home) / "verifier_ed25519.pub").read_bytes())
        self.assertFalse(verify_signature(payload, signature, verify_key))

    def test_unknown_signature_rejects(self) -> None:
        generate_keypair(self.home)
        payload = {"commit": "a" * 40}
        verify_key = load_verify_key((Path(self.home) / "verifier_ed25519.pub").read_bytes())
        self.assertFalse(verify_signature(payload, "00" * 64, verify_key))

    def test_verify_against_any_trusted_uses_ring(self) -> None:
        generate_keypair(self.home)
        key = load_signing_key(Path(self.home) / "verifier_ed25519.pem")
        payload = {"commit": "a" * 40}
        signature = sign_payload(payload, key)
        self.assertTrue(verify_against_any_trusted(payload, signature, self.home))

    def test_save_keyring_is_permissions_constrained(self) -> None:
        save_keyring(self.home, {"verifier_public_key": "k", "trusted": []})
        path = (self.home / "keyring.json")
        mode = path.stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)


if __name__ == "__main__":
    unittest.main()
