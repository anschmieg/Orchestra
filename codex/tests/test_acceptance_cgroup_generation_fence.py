from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
RUNNER = r'''
import json, os, sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
import acceptance_cgroup as cg
root = Path(sys.argv[2])
mode = sys.argv[3]
real_mkdir, real_is_file, real_rmdir = Path.mkdir, Path.is_file, Path.rmdir
old = None
rotations = 0
def make_cgroup(path, *args, **kwargs):
    real_mkdir(path, *args, **kwargs)
    if path != root:
        (path / 'cgroup.procs').touch()
        (path / 'cgroup.kill').touch()
def rotate(original):
    global old, rotations
    old = original.with_name(original.name + '-stale')
    original.rename(old)
    make_cgroup(original)
    rotations += 1
def rotate_during_inspection(path):
    if mode == 'inspect' and path.name == 'cgroup.kill' and rotations == 0:
        rotate(path.parent)
    return real_is_file(path)
def remove_cgroup(path):
    if mode == 'cleanup' and rotations == 0:
        rotate(path)
    (path / 'cgroup.procs').unlink(missing_ok=True)
    (path / 'cgroup.kill').unlink(missing_ok=True)
    return real_rmdir(path)
with patch.object(cg, 'CGROUP_ROOT', root), patch.object(cg, '_is_kernel_cgroup_v2', return_value=True), \
     patch.object(Path, 'mkdir', make_cgroup), patch.object(Path, 'is_file', rotate_during_inspection), \
     patch.object(Path, 'rmdir', remove_cgroup):
    result = cg.probe_unprivileged_delegation()
print(json.dumps({'result': result, 'rotations': rotations, 'stale_exists': old is not None and old.exists()}))
'''

@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux-only cgroup generation fencing')
class GenerationFenceTests(unittest.TestCase):
    def _probe(self, mode):
        with tempfile.TemporaryDirectory(prefix='orchestra-generation-') as dirname:
            root = Path(dirname)
            (root / 'cgroup.controllers').write_text('cpu memory')
            os.chmod(root, 0o777)
            options = {}
            if os.geteuid() == 0:
                def unprivileged():
                    os.setgroups([])
                    os.setgid(65534)
                    os.setuid(65534)
                options['preexec_fn'] = unprivileged
            child = subprocess.run([sys.executable, '-c', RUNNER, str(SCRIPTS), str(root), mode],
                text=True, capture_output=True, timeout=8, check=False, **options)
            self.assertEqual(child.returncode, 0, child.stderr)
            record = json.loads(child.stdout)
            return record

    def test_replaced_cgroup_generation_during_inspection_fails_closed(self):
        record = self._probe('inspect')
        self.assertEqual(record['rotations'], 1)
        self.assertTrue(record['stale_exists'])
        self.assertEqual(record['result']['status'], 'blocked', record)
        self.assertIn('generation', record['result']['reason'])

    def test_replaced_cgroup_generation_during_cleanup_fails_closed(self):
        record = self._probe('cleanup')
        self.assertEqual(record['rotations'], 1)
        self.assertTrue(record['stale_exists'])
        self.assertEqual(record['result']['status'], 'blocked', record)
        self.assertIn('generation', record['result']['reason'])

    def test_stable_generation_stays_delegated_unverified_not_contained(self):
        record = self._probe('none')
        self.assertEqual(record['rotations'], 0)
        self.assertEqual(record['result']['status'], 'delegated_unverified', record)

if __name__ == '__main__':
    unittest.main()
