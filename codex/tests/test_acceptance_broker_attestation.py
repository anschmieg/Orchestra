from __future__ import annotations

import json
import os
import socket
import struct
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from acceptance_broker_ipc import BROKER_SOCKET, REQUIRED_CAPABILITIES, SO_PEERPIDFD, _attest_at
import acceptance_cli


@unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "pidfd_open"),
                     "requires Linux pidfd and /proc/self/exe")
class BrokerChallengeBindingTests(unittest.TestCase):
    def _exchange(self, change=None, *, peer_uid=0, exited=None):
        class Peer:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def settimeout(self, *_): pass
            def connect(self, *_): pass
            def getsockopt(self, level, option, length):
                if option == SO_PEERPIDFD:
                    return struct.pack("i", os.pidfd_open(os.getpid(), 0))
                return struct.pack("3i", os.getpid(), peer_uid, peer_uid)
            def sendall(self, request_bytes):
                request = json.loads(request_bytes)
                self.request = request
                response = {**request, "status": "ready",
                            "capabilities": sorted(REQUIRED_CAPABILITIES),
                            "evaluator_uid": 2001}
                self.response = change(response) if change else response
            def recv(self, _):
                return (json.dumps(self.response, sort_keys=True) + "\n").encode("utf-8")
        peer = Peer()
        with patch("acceptance_broker_ipc._trusted_endpoint", return_value=None), \
             patch("acceptance_broker_ipc.socket.socket", return_value=peer), \
             patch("acceptance_broker_ipc.secrets.token_hex", return_value="a" * 64):
            if exited is None:
                return _attest_at(BROKER_SOCKET, task_id="task-A", context_id="context-A")
            with patch("acceptance_broker_ipc._peer_exited", side_effect=exited):
                return _attest_at(BROKER_SOCKET, task_id="task-A", context_id="context-A")

    def test_fresh_binding_is_transport_only_not_a_release_receipt(self):
        result = self._exchange()
        self.assertEqual(result["status"], "connected_unverified", result)
        self.assertNotIn("accepted", result.values())

    def test_replayed_nonce_from_another_task_fails_closed(self):
        def stale(reply):
            reply["task_id"] = "task-B"
            return reply
        self.assertEqual(self._exchange(stale)["status"], "blocked")

    def test_replayed_nonce_from_another_context_fails_closed(self):
        def stale(reply):
            reply["context_id"] = "context-B"
            return reply
        self.assertEqual(self._exchange(stale)["status"], "blocked")

    def test_broker_cannot_extend_challenge_expiry_in_reply(self):
        def extend(reply):
            reply["expires_monotonic_ns"] += 10_000_000_000
            return reply
        self.assertEqual(self._exchange(extend)["status"], "blocked")

    def test_broker_cannot_override_kernel_pinned_executable(self):
        def replace(reply):
            reply["verifier_executable"][1] += 1
            return reply
        self.assertEqual(self._exchange(replace)["status"], "blocked")

    def test_forged_intermediary_response_claiming_accepted_blocks(self):
        def forged(reply):
            reply["status"] = "accepted"
            return reply
        self.assertEqual(self._exchange(forged)["status"], "blocked")

    def test_nonroot_peer_cannot_impersonate_installed_broker(self):
        self.assertEqual(self._exchange(peer_uid=1001)["status"], "blocked")

    def test_kernel_verifier_uid_change_between_challenge_and_use_blocks(self):
        real_uid = os.getuid()
        with patch("acceptance_broker_ipc.os.getuid", side_effect=[real_uid, real_uid + 1]):
            self.assertEqual(self._exchange()["status"], "blocked")

    def test_challenge_expired_during_exchange_blocks(self):
        with patch("acceptance_broker_ipc.time.monotonic_ns",
                   side_effect=[100_000_000_000, 106_000_000_000]):
            self.assertEqual(self._exchange()["status"], "blocked")

    def test_broker_parent_death_does_not_authenticate_surviving_child(self):
        child = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)"],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
        try:
            self.assertEqual(self._exchange(exited=[False, True])["status"], "blocked")
            self.assertIsNone(child.poll())
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)


    def test_exec_after_parent_death_with_inherited_descriptor_cannot_authenticate(self):
        import select
        output_read, output_write = os.pipe()
        gate_read, gate_write = os.pipe()
        parent = None
        parent_pidfd = None
        child_pid = None
        child_code = (
            "import os,sys;"
            "gate=int(sys.argv[1]);out=int(sys.argv[2]);"
            "os.read(gate,1);os.set_inheritable(out,True);"
            "os.execv(sys.executable,[sys.executable,'-c',"
            "'import os,sys,time;os.write(int(sys.argv[1]),b\"EXEC_AFTER_DEATH\");time.sleep(15)',str(out)])"
        )
        parent_code = (
            "import subprocess,sys\n"
            f"code = {child_code!r}\n"
            "child=subprocess.Popen([sys.executable,'-c',code,*sys.argv[1:]],"
            "pass_fds=(int(sys.argv[1]),int(sys.argv[2])),"
            "start_new_session=True,stdin=subprocess.DEVNULL,"
            "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
            "print(child.pid,flush=True)\n"
        )
        try:
            parent = subprocess.Popen(
                [sys.executable, "-c", parent_code, str(gate_read), str(output_write)],
                pass_fds=(gate_read, output_write),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True)
            parent_pidfd = os.pidfd_open(parent.pid, 0)
            child_pid = int(parent.stdout.readline().strip())
            self.assertEqual(parent.wait(timeout=5), 0)
            os.write(gate_write, b"1")
            ready, _, _ = select.select([output_read], [], [], 5)
            self.assertTrue(ready, "exec child did not hand off inherited descriptor")
            self.assertEqual(os.read(output_read, 16), b"EXEC_AFTER_DEATH")

            class ExitedRootPeer:
                def __enter__(self): return self
                def __exit__(self, *args): pass
                def settimeout(self, *_): pass
                def connect(self, *_): pass
                def getsockopt(self, level, option, length):
                    if option == SO_PEERPIDFD:
                        return struct.pack("i", os.dup(parent_pidfd))
                    return struct.pack("3i", parent.pid, 0, 0)
                def sendall(self, _):
                    raise AssertionError("request must never reach dead parent")
            with patch("acceptance_broker_ipc._trusted_endpoint", return_value=None), \
                 patch("acceptance_broker_ipc.socket.socket", return_value=ExitedRootPeer()), \
                 patch("acceptance_broker_ipc._pidfd_matches_credential_pid", return_value=True):
                result = _attest_at(BROKER_SOCKET, task_id="task-A", context_id="context-A")
            self.assertEqual(result["status"], "blocked", result)
            self.assertIn("exited before challenge", result["reason"])
        finally:
            if child_pid is not None:
                try: os.kill(child_pid, 9)
                except ProcessLookupError: pass
            if parent is not None:
                if parent.poll() is None: parent.kill()
                parent.wait(timeout=5)
                if parent.stdout: parent.stdout.close()
                if parent.stderr: parent.stderr.close()
            for fd in (parent_pidfd, gate_read, gate_write, output_read, output_write):
                if fd is not None:
                    try: os.close(fd)
                    except OSError: pass

    def test_offline_forged_broker_cannot_make_production_admission_pass(self):
        with patch.object(acceptance_cli.sys, "flags", SimpleNamespace(isolated=1, no_site=1)), \
             patch.object(acceptance_cli.sys, "prefix", "/usr"), \
             patch.object(acceptance_cli.sys, "base_prefix", "/usr"), \
             patch.object(acceptance_cli, "_protected_path", return_value=None), \
             patch.object(acceptance_cli, "probe_broker",
                          return_value={"status": "connected_unverified"}):
            result = acceptance_cli._installed_verifier_admission_check()
        self.assertEqual(result["status"], "blocked", result)


if __name__ == "__main__":
    unittest.main()
