from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import acceptance_cli


class ProtectedDescriptorRaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="orchestra-descriptor-", dir=Path.home())
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.owners = (0, os.getuid())

    def _check(self, path):
        return acceptance_cli._protected_path(path, label="verifier code fixture", owners=self.owners)

    def _child(self, script, *paths):
        subprocess.run([sys.executable, "-c", script, *map(str, paths)],
                       check=True, capture_output=True, text=True, timeout=5)

    def test_unmodified_real_file_is_readable_to_descriptor_screen(self):
        target = self.root / "verifier.py"
        target.write_text("print('trusted')\n", encoding="utf-8")
        self.assertIsNone(self._check(target))

    def test_real_child_replaces_preverified_leaf_before_open(self):
        target = self.root / "verifier.py"
        other = self.root / "replacement.py"
        target.write_text("print('trusted')\n", encoding="utf-8")
        other.write_text("print('changed')\n", encoding="utf-8")
        original = os.lstat
        fired = False

        def snapshot_then_swap(path, *args, **kwargs):
            nonlocal fired
            entry = original(path, *args, **kwargs)
            if str(path) == str(target) and not fired:
                fired = True
                self._child("import os,sys;os.replace(sys.argv[1],sys.argv[2])",
                            other, target)
            return entry

        with patch.object(acceptance_cli.os, "lstat", side_effect=snapshot_then_swap):
            result = self._check(target)
        self.assertTrue(fired)
        self.assertIsNotNone(result, "leaf inode changed after verification snapshot")

    def test_real_child_replaces_preverified_parent_before_openat(self):
        parent = self.root / "parent"
        parent.mkdir()
        target = parent / "verifier.py"
        target.write_text("print('trusted')\n", encoding="utf-8")
        replacement = self.root / "replacement-parent"
        replacement.mkdir()
        (replacement / "verifier.py").write_text("print('changed')\n", encoding="utf-8")
        saved = self.root / "saved-parent"
        original = os.lstat
        fired = False

        def snapshot_then_swap(path, *args, **kwargs):
            nonlocal fired
            entry = original(path, *args, **kwargs)
            if str(path) == str(parent) and not fired:
                fired = True
                self._child(
                    "import os,sys;os.rename(sys.argv[1],sys.argv[2]);"
                    "os.rename(sys.argv[3],sys.argv[1])", parent, saved, replacement)
            return entry

        with patch.object(acceptance_cli.os, "lstat", side_effect=snapshot_then_swap):
            result = self._check(target)
        self.assertTrue(fired)
        self.assertIsNotNone(result, "ancestor inode changed after verification snapshot")

    def test_real_child_reopens_leaf_after_descriptor_open(self):
        target = self.root / "verifier.py"
        other = self.root / "replacement.py"
        target.write_text("print('trusted')\n", encoding="utf-8")
        other.write_text("print('changed')\n", encoding="utf-8")
        original = os.open
        fired = False

        def open_then_swap(path, flags, *args, **kwargs):
            nonlocal fired
            fd = original(path, flags, *args, **kwargs)
            if str(path) == target.name and not fired:
                fired = True
                self._child("import os,sys;os.replace(sys.argv[1],sys.argv[2])",
                            other, target)
            return fd

        with patch.object(acceptance_cli.os, "open", side_effect=open_then_swap):
            result = self._check(target)
        self.assertTrue(fired, "test must exercise actual descriptor open and child replacement")
        self.assertIsNotNone(result, "a path reopened after the pinned descriptor changed")


if __name__ == "__main__":
    unittest.main()
