from __future__ import annotations

import errno
import json
import os
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from acceptance_broker_ipc import BROKER_SOCKET, REQUIRED_CAPABILITIES, _probe_at

SO_PEERPIDFD = getattr(socket, 'SO_PEERPIDFD', 77)


@unittest.skipUnless(sys.platform.startswith('linux') and hasattr(os, 'pidfd_open'),
                     'requires Linux pidfd and real subprocesses')
class AtomicPeerIdentityTests(unittest.TestCase):
    def test_stale_peer_credential_cannot_pin_recycled_unrelated_pid(self):
        stale = subprocess.Popen([sys.executable, '-c', 'pass'], stdout=subprocess.DEVNULL)
        stale.wait(timeout=5)
        survivor = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(60)'],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        real_pidfd_open = os.pidfd_open

        class ForgedSocket:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def settimeout(self, *_): pass
            def connect(self, *_): pass
            def getsockopt(self, level, option, length):
                if option == socket.SO_PEERCRED:
                    return struct.pack('3i', stale.pid, 0, 0)
                raise OSError(errno.ENOPROTOOPT, 'kernel atomic peer identity unavailable')
            def sendall(self, request):
                self.nonce = json.loads(request)['nonce']
            def recv(self, _):
                return (json.dumps({
                    'protocol': 1, 'operation': 'probe', 'nonce': self.nonce,
                    'status': 'ready', 'capabilities': sorted(REQUIRED_CAPABILITIES),
                }) + '\n').encode()

        try:
            with patch('acceptance_broker_ipc._trusted_endpoint', return_value=None), \
                 patch('acceptance_broker_ipc.socket.socket', return_value=ForgedSocket()), \
                 patch('acceptance_broker_ipc.os.pidfd_open',
                       side_effect=lambda pid, flags: real_pidfd_open(survivor.pid, flags)):
                result = _probe_at(BROKER_SOCKET)
            self.assertEqual(result['status'], 'blocked', result)
            self.assertIsNone(survivor.poll())
        finally:
            survivor.kill()
            survivor.wait(timeout=5)

    def test_kernel_peer_pidfd_fences_real_process_after_sigkill(self):
        with tempfile.TemporaryDirectory(prefix='orchestra-peerpidfd-') as directory:
            path = str(Path(directory) / 'broker.sock')
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(path)
                listener.listen(1)
                child = subprocess.Popen([
                    sys.executable, '-c',
                    'import socket,sys,time;s=socket.socket(socket.AF_UNIX);'
                    's.connect(sys.argv[1]);time.sleep(60)', path,
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    listener.settimeout(5)
                    with listener.accept()[0] as connection:
                        try:
                            raw = connection.getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD, 4)
                        except OSError as error:
                            if error.errno in (errno.ENOPROTOOPT, errno.EINVAL):
                                self.skipTest('kernel SO_PEERPIDFD not supported')
                            raise
                        pidfd = struct.unpack('i', raw)[0]
                        try:
                            watcher = select.poll()
                            watcher.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
                            self.assertFalse(watcher.poll(0))
                            os.kill(child.pid, signal.SIGKILL)
                            self.assertEqual(child.wait(timeout=5), -signal.SIGKILL)
                            self.assertTrue(watcher.poll(1000))
                        finally:
                            os.close(pidfd)
                finally:
                    if child.poll() is None:
                        child.kill()
                    child.wait(timeout=5)


if __name__ == '__main__':
    unittest.main()
