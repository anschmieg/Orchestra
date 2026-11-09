from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux-only adversarial mount provenance')
class PhysicalContainmentProvenanceTests(unittest.TestCase):
    def test_real_cgroup_v2_superblock_is_recognized_without_containment_attestation(self):
        if not Path('/sys/fs/cgroup/cgroup.controllers').is_file():
            self.skipTest('host has no cgroup v2 mount')
        sys.path.insert(0, str(SCRIPTS))
        from acceptance_cgroup import _is_kernel_cgroup_v2
        self.assertTrue(_is_kernel_cgroup_v2(Path('/sys/fs/cgroup')))

    def test_unprivileged_owned_fake_cgroup_mount_never_reports_delegation(self):
        runner = r'''
import json, os, sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
import acceptance_cgroup as cg
root = Path(sys.argv[2]); ordinary_mkdir = Path.mkdir
# A test fixture emulates kernel creation of cgroup files on a fake, user-owned mount.
def fabricated_mkdir(path, *args, **kwargs):
    ordinary_mkdir(path, *args, **kwargs)
    (path / 'cgroup.procs').touch()
    (path / 'cgroup.kill').touch()
def fabricated_rmdir(path):
    (path / 'cgroup.procs').unlink(missing_ok=True)
    (path / 'cgroup.kill').unlink(missing_ok=True)
    return ordinary_rmdir(path)
ordinary_rmdir = Path.rmdir
with patch.object(cg, 'CGROUP_ROOT', root), patch.object(Path, 'mkdir', fabricated_mkdir), patch.object(Path, 'rmdir', fabricated_rmdir):
    print(json.dumps(cg.probe_unprivileged_delegation(), sort_keys=True))
'''
        with tempfile.TemporaryDirectory(prefix='orchestra-fake-cgroup-') as directory:
            root = Path(directory)
            (root / 'cgroup.controllers').write_text('cpu memory')
            os.chmod(root, 0o777)
            options = {}
            if os.geteuid() == 0:
                def drop_privileges():
                    os.setgroups([]); os.setgid(65534); os.setuid(65534)
                options['preexec_fn'] = drop_privileges
            result = subprocess.run([sys.executable, '-c', runner, str(SCRIPTS), str(root)],
                capture_output=True, text=True, timeout=8, check=False, **options)
            self.assertEqual(result.returncode, 0, result.stderr)
            probe = json.loads(result.stdout)
            self.assertEqual(probe['status'], 'blocked', probe)
            self.assertIn('kernel cgroup v2', probe['reason'])

if __name__ == '__main__': unittest.main()
