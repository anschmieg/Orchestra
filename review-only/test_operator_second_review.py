from __future__ import annotations
import os
import json
import socket
import stat
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path.cwd() / "codex" / "scripts"))
import acceptance_cli as cli
import acceptance_broker_ipc as ipc

class IndependentOperatorInstallationReview(unittest.TestCase):
    def test_installation_manifest_duplicate_field_rejected_before_broker_ipc(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "broker-installation.json"
            path.write_text('{"schema":1,"schema":1}', encoding="utf-8")
            old_fstat, old_lstat = os.fstat, os.lstat
            def fake_root(st):
                return SimpleNamespace(
                    st_dev=st.st_dev, st_ino=st.st_ino, st_mode=st.st_mode,
                    st_uid=0, st_nlink=st.st_nlink, st_size=st.st_size)
            with patch.object(cli, "BROKER_INSTALLATION", path), \
                 patch.object(cli, "_protected_path", return_value=None), \
                 patch.object(cli.os, "fstat", side_effect=lambda fd: fake_root(old_fstat(fd))), \
                 patch.object(cli.os, "lstat", side_effect=lambda p: fake_root(old_lstat(p))):
                result = cli._load_operator_installation()
        self.assertEqual(result["status"], "blocked", result)
        self.assertIn("provenance", result["reason"])

    @unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "pidfd_open"),
                         "Linux process identity required")
    def test_claimed_root_peer_with_other_executable_never_sends_admission_challenge(self):
        class RootLike:
            sent = 0
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def settimeout(self, *_): pass
            def connect(self, *_): pass
            def getsockopt(self, _level, option, _size):
                if option == ipc.SO_PEERPIDFD:
                    return struct.pack("i", os.pidfd_open(os.getpid(), 0))
                return struct.pack("3i", os.getpid(), 0, 0)
            def sendall(self, *_): self.sent += 1
        fake = RootLike()
        with patch.object(ipc, "_trusted_endpoint", return_value=None), \
             patch.object(ipc, "_endpoint_identity", return_value=(2, 3, 0, stat.S_IFSOCK | 0o660)), \
             patch.object(ipc.socket, "socket", return_value=fake):
            result = ipc._protected_receipt_at(
                ipc.BROKER_SOCKET, task_id="task-A", context_id="ctx-A",
                generation="gen-B", broker_verify_key=object(), ledger_dir=Path("/does-not-exist"),
                expected_broker_executable=[1, 2, stat.S_IFREG | 0o755, 0],
                expected_endpoint_identity=[2, 3, 0, stat.S_IFSOCK | 0o660],
                expected_evaluator_uid=os.getuid() + 4000)
        self.assertEqual(result["status"], "blocked", result)
        self.assertEqual(fake.sent, 0, result)
        self.assertIn("executable", result["reason"])

    def test_bad_operator_evaluator_uid_never_enters_live_exchange(self):
        with patch.object(ipc, "_trusted_endpoint", return_value=None), \
             patch.object(ipc.socket, "socket") as con:
            result = ipc._protected_receipt_at(
                ipc.BROKER_SOCKET, task_id="task-A", context_id="ctx-A",
                generation="gen-B", broker_verify_key=object(), ledger_dir=Path("/does-not-exist"),
                expected_evaluator_uid=os.getuid())
        self.assertEqual(result["status"], "blocked", result)
        con.assert_not_called()

    def test_operator_socket_identity_type_mismatch_rejected_before_exchange(self):
        with patch.object(ipc, "_trusted_endpoint", return_value=None), \
             patch.object(ipc.socket, "socket") as con:
            result = ipc._protected_receipt_at(
                ipc.BROKER_SOCKET, task_id="task-A", context_id="ctx-A",
                generation="gen-B", broker_verify_key=object(), ledger_dir=Path("/does-not-exist"),
                expected_endpoint_identity=[2, 3, True, stat.S_IFSOCK | 0o660])
        self.assertEqual(result["status"], "blocked", result)
        con.assert_not_called()

if __name__ == "__main__":
    unittest.main()
