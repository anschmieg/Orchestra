from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CLI = Path(__file__).resolve().parents[1] / "scripts" / "acceptance_cli.py"
FORGED = '{"status":"accepted","source":"attacker-bootstrap"}'


class PreInitializationProvenanceCounterexamples(unittest.TestCase):
    """Disposable same-UID OS processes; none is a protected verifier install."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="orchestra-preinit-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.checkout = self.root / "implementer-checkout"
        self.checkout.mkdir()
        self._inject_sitecustomize()

    def _inject_sitecustomize(self):
        (self.checkout / "sitecustomize.py").write_text(
            "import os\n"
            "os.write(1, b'" + FORGED + "\\n')\n"
            "os._exit(0)\n", encoding="utf-8"
        )

    def _launch(self, executable, *, isolated, env=None, script=CLI):
        argv = [str(executable)]
        if isolated:
            argv.append("-I")
        argv.extend([str(script), "--help"])
        return subprocess.run(argv, env=env, capture_output=True, text=True, timeout=15, check=False)

    def test_inherited_pythonpath_forges_before_trusted_cli_imports(self):
        env = {**os.environ, "PYTHONPATH": str(self.checkout)}
        env.pop("PYTHONHOME", None)
        result = self._launch(sys.executable, isolated=False, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(FORGED, result.stdout)
        self.assertNotIn("usage:", result.stdout)

    def test_isolated_parent_ignores_checkout_sitecustomize(self):
        env = {**os.environ, "PYTHONPATH": str(self.checkout)}
        env.pop("PYTHONHOME", None)
        result = self._launch(sys.executable, isolated=True, env=env)
        self.assertNotIn(FORGED, result.stdout + result.stderr)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("usage:", result.stdout)

    def test_attacker_interpreter_ignores_isolation_flag(self):
        interpreter = self.checkout / "python3"
        interpreter.write_text(
            "#!/bin/sh\nprintf '%s\\n' '" + FORGED + "'\nexit 0\n",
            encoding="utf-8",
        )
        interpreter.chmod(0o755)
        result = self._launch(interpreter, isolated=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(FORGED, result.stdout)

    def test_swappable_interpreter_symlink_ignores_isolation_flag(self):
        symlink = self.checkout / "python-symlink"
        symlink.symlink_to(sys.executable)
        interpreter = self.checkout / "attacker-python"
        interpreter.write_text(
            "#!/bin/sh\nprintf '%s\\n' '" + FORGED + "'\nexit 0\n",
            encoding="utf-8",
        )
        interpreter.chmod(0o755)
        symlink.unlink()
        symlink.symlink_to(interpreter)
        result = self._launch(symlink, isolated=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(FORGED, result.stdout)

    def test_replaceable_cli_entrypoint_forges_under_isolated_python(self):
        unprotected_install = self.root / "unprotected-verifier-install"
        unprotected_install.mkdir()
        entrypoint = unprotected_install / "acceptance_cli.py"
        shutil.copy2(CLI, entrypoint)
        entrypoint.write_text("print(" + repr(FORGED) + ")" + chr(10), encoding="utf-8")
        result = self._launch(sys.executable, isolated=True, script=entrypoint)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(FORGED, result.stdout)

    def test_writable_venv_pth_executes_even_with_isolated_python(self):
        venv_dir = self.checkout / "mutable-python-install"
        create = subprocess.run(
            [sys.executable, "-m", "venv", "--without-pip", str(venv_dir)],
            capture_output=True, text=True, timeout=30, check=False,
        )
        self.assertEqual(create.returncode, 0, create.stderr)
        site_dir = next((venv_dir / "lib").glob("python*/site-packages"))
        (site_dir / "attacker.pth").write_text(
            "import os; os.write(1, " + repr((FORGED + "\n").encode()) + "); os._exit(0)\n",
            encoding="utf-8",
        )
        result = self._launch(venv_dir / "bin" / "python", isolated=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(FORGED, result.stdout)


if __name__ == "__main__":
    unittest.main()
