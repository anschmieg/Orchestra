from __future__ import annotations

import errno
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux cgroup v2 only')
class CgroupDelegationNegativeTests(unittest.TestCase):
    def test_real_unprivileged_cgroup_probe_never_attests_containment(self) -> None:
        runner = '''
import json, sys
sys.path.insert(0, sys.argv[1])
from acceptance_cgroup import probe_unprivileged_delegation
print(json.dumps(probe_unprivileged_delegation(), sort_keys=True))
'''
        options = {}
        if os.geteuid() == 0:
            def drop_privileges() -> None:
                os.setgroups([])
                os.setgid(65534)
                os.setuid(65534)
            options['preexec_fn'] = drop_privileges
        result = subprocess.run(
            [sys.executable, '-c', runner, str(SCRIPTS)],
            capture_output=True, text=True, timeout=8, check=False, **options,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        probe = json.loads(result.stdout)
        self.assertIn(probe['status'], {'blocked', 'delegated_unverified'})
        self.assertNotIn(probe['status'], {'ready', 'accepted', 'contained'})
        if probe['status'] == 'blocked':
            self.assertTrue(probe['reason'])
            if 'errno' in probe:
                self.assertIn(probe['errno'], {errno.EACCES, errno.EPERM, errno.EROFS, errno.ENOSPC, errno.EDQUOT})

    def test_missing_installed_broker_blocks_evaluator_despite_live_survivor(self) -> None:
        sys.path.insert(0, str(SCRIPTS))
        from acceptance_gate import run_check
        with tempfile.TemporaryDirectory(prefix='orchestra-cgroup-negative-') as directory:
            marker = Path(directory) / 'wrongly-ran'
            survivor = subprocess.Popen(
                [sys.executable, '-c', 'import time; time.sleep(20)'],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            try:
                result = run_check(Path(directory), {
                    'name': 'untrusted',
                    'command': [sys.executable, '-c', f'open({str(marker)!r}, "w").write("PASS")'],
                })
                self.assertEqual(result['status'], 'blocked')
                self.assertIn('OS-principal isolation broker', result['reason'])
                self.assertFalse(marker.exists())
                self.assertIsNone(survivor.poll())
            finally:
                survivor.kill()
                survivor.wait(timeout=5)


if __name__ == '__main__':
    unittest.main()
