from __future__ import annotations

import os
import stat
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "codex" / "scripts"))
sys.path.insert(0, str(ROOT / "codex" / "tests"))
import test_acceptance_rotation as rotation


class IndependentPostReceiptAdversarialReview(unittest.TestCase):
    """Additional unprivileged negatives. Never claims installed privileged GO."""

    def negative(self, tamper):
        fixture = rotation.RotationAcrossRefusedIPC(
            methodName="test_generation_manifest_replaced_while_ipc_is_refused")
        fixture.setUp()
        try:
            return fixture.refusal(lambda: tamper(fixture))
        finally:
            fixture.doCleanups()

    def test_executable_inode_pin_rotated_while_broker_refused(self):
        def tamper(f):
            f.manifest["broker_executable"][1] += 1
            f.write_manifest()
        reason = self.negative(tamper)
        self.assertIn("installation", reason)
        self.assertIn("changed", reason)

    def test_verifier_evaluator_separation_changed_while_broker_refused(self):
        def tamper(f):
            f.manifest["evaluator_uid"] = f.manifest["verifier_uid"]
            f.write_manifest()
        reason = self.negative(tamper)
        self.assertIn("installation", reason)
        self.assertIn("changed", reason)

    def test_protected_keyring_same_content_swapped_inode(self):
        def tamper(f):
            dest = f.home / "keyring.json"
            replacement = f.home / "replacement-keyring"
            replacement.write_bytes(dest.read_bytes())
            replacement.replace(dest)
        reason = self.negative(tamper)
        self.assertIn("installation", reason)
        self.assertIn("changed", reason)

    def test_kernel_cgroup_change_during_broker_refusal(self):
        moved = {"now": False}
        real_read = Path.read_bytes
        def read_bytes(path):
            if str(path) == "/proc/self/cgroup":
                return b"0::/after\n" if moved["now"] else b"0::/before\n"
            return real_read(path)
        with patch.object(Path, "read_bytes", read_bytes):
            reason = self.negative(lambda f: moved.__setitem__("now", True))
        self.assertIn("installation", reason)
        self.assertIn("changed", reason)



class IndependentRestartReplayNegatives(unittest.TestCase):
    """Separate real processes and SIGKILL; deliberately NOT an installed-broker positive."""

    def _python(self, code, *args, wait_for_line=False):
        import subprocess
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT / "codex" / "scripts")
        cmd = [sys.executable, "-u", "-c", code, *args]
        if wait_for_line:
            return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, env=env)
        return subprocess.run(cmd, capture_output=True, text=True, check=False,
                              timeout=8, env=env)

    def _ledger(self):
        import tempfile
        temp = tempfile.TemporaryDirectory(prefix="orchestra-sigkill-replay-")
        self.addCleanup(temp.cleanup)
        ledger = Path(temp.name) / "admissions"
        ledger.mkdir(mode=0o700)
        (ledger / "used-nonces").touch(mode=0o600)
        return ledger

    def test_cryptographically_valid_prior_receipt_rejected_after_real_sigkill_rotation(self):
        import json
        import secrets
        import time
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from acceptance_keyring import load_verify_key
        import acceptance_receipt as receipt

        ledger = self._ledger()
        issued = time.monotonic_ns()
        challenge = {
            "nonce": secrets.token_hex(32),
            "task_id": "test-task", "context_id": "test-context",
            "generation": "generation-before-restart",
            "issued_monotonic_ns": issued,
            "expires_monotonic_ns": issued + 5_000_000_000,
            "verifier_pid": os.getpid(), "verifier_uid": os.getuid(),
            "verifier_euid": os.geteuid(),
            "verifier_executable": receipt._executable_identity("/proc/self/exe"),
        }
        signer = r'''
import json, os, signal, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from acceptance_receipt import _executable_identity
key = Ed25519PrivateKey.generate()  # ephemeral unprivileged test key, never installed
body = {
    **json.loads(sys.argv[1]),
    "protocol": 3, "operation": "protected-admission",
    "evaluator_pid": os.getpid(), "evaluator_uid": os.getuid() + 2000,
    "evaluator_executable": _executable_identity("/proc/self/exe"),
}
canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
signed = {**body, "signature": key.sign(canonical).hex()}
public = key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()
print(json.dumps({"receipt": signed, "public": public}), flush=True)
signal.pause()
'''
        process = self._python(signer, json.dumps(challenge), wait_for_line=True)
        try:
            packet = process.stdout.readline()
            self.assertTrue(packet, "signer failed before receipt production")
            delivered = json.loads(packet)
            prior = delivered["receipt"]
            old_key = load_verify_key(delivered["public"])
            canonical = json.dumps({k: v for k, v in prior.items()
                                    if k != "signature"}, sort_keys=True,
                                   separators=(",", ":")).encode()
            old_key.verify(bytes.fromhex(prior["signature"]), canonical)
            signing_pid = process.pid
        finally:
            process.kill()  # actual kernel SIGKILL, not a mocked failure
            self.assertEqual(process.wait(timeout=5), -9)
            process.stdout.close()
            process.stderr.close()
        self.assertEqual(prior["evaluator_pid"], signing_pid)
        self.assertNotEqual(signing_pid, os.getpid())

        # The previously valid Ed25519 signature is not a valid installed
        # admission: no distinct-UID evaluator/protected key exists in CI.
        rotated_key = Ed25519PrivateKey.generate().public_key()
        rotated_key_result = receipt.verify_one_use_receipt(prior, challenge, rotated_key, ledger)
        self.assertEqual(rotated_key_result["status"], "blocked")
        self.assertIn("signature invalid", rotated_key_result["reason"])

        new_generation = {**challenge, "generation": "generation-after-restart"}
        generation_result = receipt.verify_one_use_receipt(prior, new_generation, old_key, ledger)
        self.assertEqual(generation_result["status"], "blocked")
        self.assertIn("binding mismatch: generation", generation_result["reason"])

        # A restarted verifier has a different PID; no PID-recycle claim is made.
        next_pid = {**challenge, "verifier_pid": challenge["verifier_pid"] + 1}
        pid_result = receipt.verify_one_use_receipt(prior, next_pid, old_key, ledger)
        self.assertEqual(pid_result["status"], "blocked")
        self.assertIn("binding mismatch: verifier_pid", pid_result["reason"])

        crashed_result = receipt.verify_one_use_receipt(prior, challenge, old_key, ledger)
        self.assertEqual(crashed_result["status"], "blocked")
        self.assertEqual((ledger / "used-nonces").read_text(), "")

    def test_fsynced_old_replay_ledger_rejects_reuse_after_sigkill_restart(self):
        import json
        import secrets
        nonce = secrets.token_hex(32)
        ledger = self._ledger()
        code = r'''
import json, signal, sys
from pathlib import Path
from acceptance_receipt import _consume_once
answer = _consume_once(Path(sys.argv[1]), sys.argv[2])
print(json.dumps(answer), flush=True)
if len(sys.argv) > 3:
    signal.pause()
'''
        first = self._python(code, str(ledger), nonce, "stay", wait_for_line=True)
        try:
            line = first.stdout.readline()
            self.assertTrue(line, "ledger writer failed before fsynced record")
            self.assertEqual(json.loads(line)["status"], "recorded")
            pid_before = first.pid
        finally:
            first.kill()
            self.assertEqual(first.wait(timeout=5), -9)
            first.stdout.close()
            first.stderr.close()
        after = self._python(code, str(ledger), nonce)
        self.assertEqual(after.returncode, 0, after.stderr)
        self.assertNotEqual(pid_before, os.getpid())
        replay = json.loads(after.stdout)
        self.assertEqual(replay["status"], "blocked", replay)
        self.assertIn("replay detected", replay["reason"])
        self.assertEqual((ledger / "used-nonces").read_text(), nonce + "\n")


if __name__ == "__main__":
    unittest.main()
