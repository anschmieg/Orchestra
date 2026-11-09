from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import acceptance_cli


class VerifierProcessCodeBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="orchestra-exec-boundary-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.implementer = self.root / "implementer-checkout"
        self.implementer.mkdir()
        self.protected = self.root / "protected-verifier-home"
        self.protected.mkdir(mode=0o700)
        (self.protected / "keyring.json").write_text('{"verifier_public_key":null,"trusted":[]}', encoding="utf-8")
        (self.protected / "keyring.json").chmod(0o600)
        self.attacker = self.root / "attacker-python"
        self.attacker.mkdir()
        (self.attacker / "sitecustomize.py").write_text(
            "import os\n"
            "os.write(1, b'{\"status\":\"accepted\",\"forged\":true}\\n')\n"
            "os._exit(0)\n", encoding="utf-8",
        )

    def _run_untrusted_pythonpath(self, value):
        with (patch.object(acceptance_cli, "VERIFIER_HOME", self.protected),
              patch.dict(os.environ, {"PYTHONPATH": value, "PYTHONINSPECT": "", "PYTHONSTARTUP": ""})):
            return acceptance_cli._run(self.implementer, ["acceptance_gate.py", "--help"])

    def test_absolute_pythonpath_sitecustomize_cannot_forge_verifier_pass(self):
        code, stdout, stderr = self._run_untrusted_pythonpath(str(self.attacker))
        self.assertEqual(code, 0, stderr)
        self.assertIn("usage:", stdout)
        self.assertNotIn('"status":"accepted"', stdout)

    def test_cwd_relative_pythonpath_sitecustomize_cannot_forge_verifier_pass(self):
        (self.implementer / "sitecustomize.py").write_text(
            (self.attacker / "sitecustomize.py").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        code, stdout, stderr = self._run_untrusted_pythonpath(".")
        self.assertEqual(code, 0, stderr)
        self.assertIn("usage:", stdout)
        self.assertNotIn('"status":"accepted"', stdout)

    def test_child_process_environment_excludes_implementer_loader_controls(self):
        with (patch.object(acceptance_cli, "VERIFIER_HOME", self.protected),
              patch.dict(os.environ, {"PYTHONPATH": str(self.attacker), "PYTHONHOME": str(self.attacker),
                                      "LD_PRELOAD": "/tmp/attacker.so", "GIT_CONFIG_GLOBAL": str(self.attacker / "config")})):
            with patch.object(acceptance_cli.subprocess, "run") as invoke:
                invoke.return_value.returncode = 1
                invoke.return_value.stdout = ""
                invoke.return_value.stderr = ""
                acceptance_cli._run(self.implementer, ["acceptance_gate.py", "--help"])
                argv = invoke.call_args.args[0]
                kwargs = invoke.call_args.kwargs
                self.assertIn("-I", argv)
                self.assertEqual(kwargs["cwd"], str(self.protected))
                for variable in ("PYTHONPATH", "PYTHONHOME", "LD_PRELOAD", "GIT_CONFIG_GLOBAL"):
                    self.assertNotIn(variable, kwargs["env"])


if __name__ == "__main__":
    unittest.main()
