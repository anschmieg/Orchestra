from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest


class ProcessSeparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = pathlib.Path(__file__).resolve().parents[2]
        cls.scripts = cls.base / "codex/scripts"

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="orchestra-process-")
        self.addCleanup(self.temporary.cleanup)
        base = pathlib.Path(self.temporary.name)
        self.impl_home = base / "impl-home"
        self.verify_home = base / "verify-home"
        self.impl_repo = base / "impl-repo"
        for directory in (self.impl_home, self.verify_home, self.impl_repo):
            directory.mkdir()

    def _run_script(self, code, home=None, env_extra=None):
        env = os.environ.copy()
        if env_extra:
            env.update(env_extra)
        proc = subprocess.run(
            [sys.executable, "-c", code],
            cwd=str(self.base),
            capture_output=True, text=True, env=env,
        )
        return proc

    def test_implementer_cannot_forge_without_private_key(self):
        keygen = subprocess.run([
            sys.executable, "-c",
            f"import sys; sys.path.insert(0, '{self.scripts}'); "
            f"from acceptance_keyring import generate_keypair; import pathlib; "
            f"generate_keypair(pathlib.Path('{self.verify_home}'))"
        ], cwd=str(self.base), capture_output=True, text=True)
        self.assertEqual(keygen.returncode, 0)
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=str(self.impl_repo), check=True)
        subprocess.run(["git", "config", "user.name", "Impl"], cwd=str(self.impl_repo), check=True)
        subprocess.run(["git", "config", "user.email", "impl@test"], cwd=str(self.impl_repo), check=True)
        (self.impl_repo / "file.txt").write_text("content\n")
        subprocess.run(["git", "add", "file.txt"], cwd=str(self.impl_repo), check=True)
        subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=str(self.impl_repo), check=True)
        unsigned_code = f"""
import sys; sys.path.insert(0, '{self.scripts}')
from acceptance_evidence import build_payload, write_envelope
import pathlib
payload = build_payload(pathlib.Path('{self.impl_repo}'), files=['file.txt'])
write_envelope(pathlib.Path('{self.impl_home}/unsigned.json'),
    {{'payload': payload, 'signature': '00'*64, 'algorithm': 'ed25519'}})
"""
        proc = self._run_script(unsigned_code)
        self.assertEqual(proc.returncode, 0)
        forge_verify_code = f"""
import sys; sys.path.insert(0, '{self.scripts}')
from acceptance_evidence import load_envelope, verify
import pathlib
env = load_envelope(pathlib.Path('{self.impl_home}/unsigned.json'))
res = verify(env, home=pathlib.Path('{self.impl_home}'))
print(res)
"""
        proc = self._run_script(forge_verify_code)
        self.assertEqual(proc.returncode, 0)
        output = proc.stdout
        self.assertIn("blocked", output)
        self.assertIn("signature", output)
        self.assertFalse((self.impl_home / "verifier_ed25519.pem").exists())
        self.assertTrue((self.verify_home / "verifier_ed25519.pem").exists())

    def test_separate_process_validates_with_only_public_key(self):
        keygen = subprocess.run([
            sys.executable, "-c",
            f"import sys; sys.path.insert(0, '{self.scripts}'); "
            f"from acceptance_keyring import generate_keypair; import pathlib; "
            f"generate_keypair(pathlib.Path('{self.verify_home}'))"
        ], cwd=str(self.base), capture_output=True, text=True)
        self.assertEqual(keygen.returncode, 0)
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=str(self.impl_repo), check=True)
        subprocess.run(["git", "config", "user.name", "Impl"], cwd=str(self.impl_repo), check=True)
        subprocess.run(["git", "config", "user.email", "impl@test"], cwd=str(self.impl_repo), check=True)
        (self.impl_repo / "file.txt").write_text("content\n")
        subprocess.run(["git", "add", "file.txt"], cwd=str(self.impl_repo), check=True)
        subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=str(self.impl_repo), check=True)
        unsigned_code = f"""
import sys; sys.path.insert(0, '{self.scripts}')
from acceptance_evidence import build_payload, write_envelope
import pathlib
payload = build_payload(pathlib.Path('{self.impl_repo}'), files=['file.txt'])
write_envelope(pathlib.Path('{self.impl_home}/unsigned.json'),
    {{'payload': payload, 'signature': '00'*64, 'algorithm': 'ed25519'}})
"""
        proc = self._run_script(unsigned_code)
        self.assertEqual(proc.returncode, 0)
        sign_code = f"""
import sys; sys.path.insert(0, '{self.scripts}')
from acceptance_evidence import load_envelope, sign, write_envelope
import pathlib
env = load_envelope(pathlib.Path('{self.impl_home}/unsigned.json'))
signed = sign(env['payload'], pathlib.Path('{self.verify_home}/verifier_ed25519.pem'))
write_envelope(pathlib.Path('{self.impl_home}/signed.json'), signed)
"""
        proc = self._run_script(sign_code)
        self.assertEqual(proc.returncode, 0)
        validate_code = f"""
import sys; sys.path.insert(0, '{self.scripts}')
from acceptance_evidence import load_envelope, verify
import pathlib
env = load_envelope(pathlib.Path('{self.impl_home}/signed.json'))
res = verify(env, home=pathlib.Path('{self.verify_home}'))
print(res)
"""
        proc = self._run_script(validate_code)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("'status': 'ok'", proc.stdout)

    def test_implementer_tampering_detected_across_process(self):
        keygen = subprocess.run([
            sys.executable, "-c",
            f"import sys; sys.path.insert(0, '{self.scripts}'); "
            f"from acceptance_keyring import generate_keypair; import pathlib; "
            f"generate_keypair(pathlib.Path('{self.verify_home}'))"
        ], cwd=str(self.base), capture_output=True, text=True)
        self.assertEqual(keygen.returncode, 0)
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=str(self.impl_repo), check=True)
        subprocess.run(["git", "config", "user.name", "Impl"], cwd=str(self.impl_repo), check=True)
        subprocess.run(["git", "config", "user.email", "impl@test"], cwd=str(self.impl_repo), check=True)
        (self.impl_repo / "file.txt").write_text("original\n")
        subprocess.run(["git", "add", "file.txt"], cwd=str(self.impl_repo), check=True)
        subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=str(self.impl_repo), check=True)
        unsigned_code = f"""
import sys; sys.path.insert(0, '{self.scripts}')
from acceptance_evidence import build_payload, write_envelope
import pathlib
payload = build_payload(pathlib.Path('{self.impl_repo}'), files=['file.txt'])
write_envelope(pathlib.Path('{self.impl_home}/unsigned.json'),
    {{'payload': payload, 'signature': '00'*64, 'algorithm': 'ed25519'}})
"""
        self._run_script(unsigned_code)
        sign_code = f"""
import sys; sys.path.insert(0, '{self.scripts}')
from acceptance_evidence import load_envelope, sign, write_envelope
import pathlib
env = load_envelope(pathlib.Path('{self.impl_home}/unsigned.json'))
signed = sign(env['payload'], pathlib.Path('{self.verify_home}/verifier_ed25519.pem'))
write_envelope(pathlib.Path('{self.impl_home}/signed.json'), signed)
"""
        self._run_script(sign_code)
        evidence_path = self.impl_home / "signed.json"
        evidence = json.loads(evidence_path.read_text())
        evidence['payload']['files']['file.txt'] = 'tampered_hash'
        evidence_path.write_text(json.dumps(evidence, sort_keys=True))
        validate_code = f"""
import sys; sys.path.insert(0, '{self.scripts}')
from acceptance_evidence import load_envelope, verify
import pathlib
env = load_envelope(pathlib.Path('{self.impl_home}/signed.json'))
res = verify(env, home=pathlib.Path('{self.verify_home}'))
print(res)
"""
        proc = self._run_script(validate_code)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("blocked", proc.stdout)


if __name__ == "__main__":
    unittest.main()
