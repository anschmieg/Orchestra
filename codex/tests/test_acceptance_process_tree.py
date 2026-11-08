"""Real Linux escaped-child regression; never treats a synthetic process as a broker."""
from __future__ import annotations

import ctypes
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

BROKER_SIMULATOR = r'''
import os
import sys
import time

marker = sys.argv[1]
first = os.fork()
if first == 0:
    os.setsid()
    second = os.fork()
    if second:
        os._exit(0)
    with open(marker, 'w', encoding='ascii') as output:
        output.write(f'{os.getpid()} {os.getpgrp()}\n')
    while True:
        time.sleep(60)
os.waitpid(first, 0)
while True:
    time.sleep(60)
'''


def _alive(pid: int) -> bool:
    """Exclude zombies: kill(pid, 0) also succeeds for unreaped zombies."""
    try:
        stat = Path(f'/proc/{pid}/stat').read_text(encoding='ascii')
    except FileNotFoundError:
        return False
    return stat.rsplit(')', 1)[1].split()[0] not in {'Z', 'X'}


def _subreaper(on: bool) -> None:
    # This operation affects only the test process, not the host's init/systemd.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, int(on), 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), 'PR_SET_CHILD_SUBREAPER')


@unittest.skipUnless(sys.platform.startswith('linux') and Path('/proc/self/stat').exists(),
                     'requires Linux procfs and double-fork')
class RealEscapedChildTests(unittest.TestCase):
    def test_supervisor_sigkill_double_fork_survives_but_restarted_gate_blocks(self) -> None:
        """Physical fork/SIGKILL/cleanup; no root broker or mock containment claim."""
        _subreaper(True)
        broker = None
        escape_pid = None
        try:
            with tempfile.TemporaryDirectory(prefix='orchestra-escape-') as directory:
                marker = Path(directory, 'escaped.pid')
                broker = subprocess.Popen(
                    [sys.executable, '-c', BROKER_SIMULATOR, str(marker)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, start_new_session=True,
                )
                deadline = time.monotonic() + 5
                while not marker.exists() and time.monotonic() < deadline:
                    if broker.poll() is not None:
                        self.fail('simulated supervisor exited before double-fork')
                    time.sleep(0.02)
                self.assertTrue(marker.exists(), 'double-fork child did not start')
                escape_pid, escaped_pgid = map(int, marker.read_text().split())
                self.assertTrue(_alive(escape_pid))
                self.assertNotEqual(escaped_pgid, broker.pid)

                os.kill(broker.pid, signal.SIGKILL)
                self.assertEqual(broker.wait(timeout=5), -signal.SIGKILL)
                self.assertTrue(_alive(escape_pid),
                                'escaped child unexpectedly reaped by supervisor SIGKILL')

                # Fresh evaluator process (restart) cannot infer PASS from the
                # supervisor's disappearance, even while escaped code is alive.
                root = str(Path(__file__).resolve().parents[1] / 'scripts')
                runner = '''
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from acceptance_gate import run_check
result = run_check(Path.cwd(), {'name':'escaped', 'command':[sys.executable, '-c', 'pass']})
print(json.dumps(result))
'''
                restarted = subprocess.run(
                    [sys.executable, '-c', runner, root],
                    capture_output=True, text=True, timeout=8, check=False,
                )
                self.assertEqual(restarted.returncode, 0, restarted.stderr)
                result = json.loads(restarted.stdout)
                self.assertEqual(result['status'], 'blocked')
                self.assertIn('OS-principal isolation broker', result['reason'])
        finally:
            # Never leave an escaped child running, including assertion failures.
            try:
                if escape_pid is not None:
                    try:
                        os.kill(escape_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        os.waitpid(escape_pid, 0)  # subreaper owns adopted grandchild
                    except ChildProcessError:
                        pass
                if broker is not None:
                    if broker.poll() is None:
                        broker.kill()
                    broker.wait(timeout=5)
            finally:
                _subreaper(False)
            if escape_pid is not None:
                self.assertFalse(_alive(escape_pid), 'escaped child cleanup failed')


if __name__ == '__main__':
    unittest.main()
