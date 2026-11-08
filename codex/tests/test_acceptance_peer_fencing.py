from __future__ import annotations

import ctypes
import json
import os
import signal
import socket
import struct
import subprocess
import tempfile
import time
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from acceptance_broker_ipc import BROKER_SOCKET, _probe_at, REQUIRED_CAPABILITIES


@unittest.skipUnless(sys.platform.startswith('linux') and hasattr(os, 'pidfd_open'),
                     'requires real Linux pidfd identities')
class RealPeerIdentityFencingTests(unittest.TestCase):
    def test_dead_claimed_broker_with_surviving_concurrent_process_fails_closed(self):
        options = {}
        if os.geteuid() == 0:
            def unprivileged():
                os.setgroups([])
                os.setgid(65534)
                os.setuid(65534)
            options['preexec_fn'] = unprivileged
        broker = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(60)'],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, **options)
        survivor = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(60)'],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, **options)
        try:
            class SocketFixture:
                def __enter__(self): return self
                def __exit__(self, *args): pass
                def settimeout(self, *_): pass
                def connect(self, *_): pass
                def getsockopt(self, *_): return struct.pack('3i', broker.pid, 0, 0)
                def sendall(self, request):
                    self.nonce = json.loads(request)['nonce']
                def recv(self, _):
                    os.kill(broker.pid, signal.SIGKILL)
                    broker.wait(timeout=5)
                    return (json.dumps({
                        'protocol': 1, 'operation': 'probe', 'nonce': self.nonce,
                        'status': 'ready', 'capabilities': sorted(REQUIRED_CAPABILITIES),
                    }) + '\n').encode()
            with patch('acceptance_broker_ipc._trusted_endpoint', return_value=None), \
                 patch('acceptance_broker_ipc.socket.socket', return_value=SocketFixture()):
                result = _probe_at(BROKER_SOCKET)
            self.assertEqual(result['status'], 'blocked', result)
            self.assertIsNone(survivor.poll(), 'independent survivor must remain alive during probe')
        finally:
            for process in (broker, survivor):
                if process.poll() is None: process.kill()
                process.wait(timeout=5)

    def test_restarted_probe_rejects_stale_broker_after_sigkill_double_fork(self):
        # The real unprivileged orphan remains alive; only the socket and
        # SO_PEERCRED claim are simulated (no broker or cgroup installed).
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(36, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), 'PR_SET_CHILD_SUBREAPER')
        supervisor = None
        escaped_pid = None
        try:
            with tempfile.TemporaryDirectory(prefix='orchestra-fencing-') as directory:
                os.chmod(directory, 0o777)
                marker = Path(directory, 'escaped.pid')
                script = """
import os,sys,time
kid = os.fork()
if kid == 0:
    os.setsid()
    grandkid = os.fork()
    if grandkid: os._exit(0)
    with open(sys.argv[1], 'w') as f: f.write(str(os.getpid()))
    while True: time.sleep(60)
os.waitpid(kid, 0)
while True: time.sleep(60)
"""
                options = {}
                if os.geteuid() == 0:
                    def unprivileged():
                        os.setgroups([])
                        os.setgid(65534)
                        os.setuid(65534)
                    options['preexec_fn'] = unprivileged
                supervisor = subprocess.Popen([sys.executable, '-c', script, str(marker)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, **options)
                deadline = time.monotonic() + 5
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(marker.exists(), 'double fork did not reach live orphan')
                escaped_pid = int(marker.read_text())
                self.assertTrue(Path(f'/proc/{escaped_pid}').exists())
                os.kill(supervisor.pid, signal.SIGKILL)
                self.assertEqual(supervisor.wait(timeout=5), -signal.SIGKILL)
                self.assertTrue(Path(f'/proc/{escaped_pid}').exists(),
                                'orphan unexpectedly vanished after supervisor SIGKILL')
                restarted = """
import json,struct,sys
from unittest.mock import patch
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import acceptance_broker_ipc as broker
class StalePeer:
    def __enter__(self): return self
    def __exit__(self, *a): pass
    def settimeout(self, *a): pass
    def connect(self, *a): pass
    def getsockopt(self, *a): return struct.pack('3i', int(sys.argv[2]), 0, 0)
    def sendall(self, request): self.nonce=json.loads(request)['nonce']
    def recv(self, _):
        return (json.dumps({'protocol':1,'operation':'probe','nonce':self.nonce,
            'status':'ready','capabilities':sorted(broker.REQUIRED_CAPABILITIES)})+'\\n').encode()
with patch('acceptance_broker_ipc._trusted_endpoint',return_value=None), \
     patch('acceptance_broker_ipc.socket.socket',return_value=StalePeer()):
    print(json.dumps(broker._probe_at(broker.BROKER_SOCKET)))
"""
                result = subprocess.run([sys.executable, '-c', restarted,
                                        str(Path(__file__).resolve().parents[1] / 'scripts'),
                                        str(supervisor.pid)], capture_output=True, text=True,
                                        timeout=8, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout)['status'], 'blocked')
                self.assertTrue(Path(f'/proc/{escaped_pid}').exists())
        finally:
            if supervisor is not None:
                if supervisor.poll() is None: supervisor.kill()
                supervisor.wait(timeout=5)
            if escaped_pid is not None:
                try: os.kill(escaped_pid, signal.SIGKILL)
                except ProcessLookupError: pass
                try: os.waitpid(escaped_pid, 0)
                except ChildProcessError: pass
            libc.prctl(36, 0, 0, 0, 0)

    def test_already_dead_claimed_broker_pid_cannot_be_replayed(self):
        proc = subprocess.Popen([sys.executable, '-c', 'pass'], stdout=subprocess.DEVNULL)
        proc.wait(timeout=5)
        class SocketFixture:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def settimeout(self, *_): pass
            def connect(self, *_): pass
            def getsockopt(self, *_): return struct.pack('3i', proc.pid, 0, 0)
            def sendall(self, request): self.nonce = json.loads(request)['nonce']
            def recv(self, _):
                return (json.dumps({'protocol': 1, 'operation': 'probe', 'nonce': self.nonce,
                                    'status': 'ready', 'capabilities': sorted(REQUIRED_CAPABILITIES)}) + '\n').encode()
        with patch('acceptance_broker_ipc._trusted_endpoint', return_value=None), \
             patch('acceptance_broker_ipc.socket.socket', return_value=SocketFixture()):
            result = _probe_at(BROKER_SOCKET)
        self.assertEqual(result['status'], 'blocked', result)

if __name__ == '__main__': unittest.main()
