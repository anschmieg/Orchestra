from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path.cwd() / "codex" / "scripts"))
import acceptance_broker_ipc as ipc
import acceptance_cli
import acceptance_gate


class IndependentProtectedAdmissionReview(unittest.TestCase):
    def _installed(self, claim):
        with patch.object(acceptance_cli.sys, "flags", SimpleNamespace(isolated=1, no_site=1)), \
             patch.object(acceptance_cli.sys, "prefix", "/usr"), \
             patch.object(acceptance_cli.sys, "base_prefix", "/usr"), \
             patch.object(acceptance_cli, "_protected_path", return_value=None), \
             patch.object(acceptance_cli, "probe_broker", return_value=claim):
            return acceptance_cli._installed_verifier_admission_check()

    def test_simulated_signed_broker_cannot_satisfy_installed_admission(self):
        with patch.object(ipc, "_protected_receipt_at",
                          return_value={"status": "verified_uninstalled"}):
            result = self._installed({"status": "connected_unverified"})
        self.assertEqual(result["status"], "blocked", result)
        self.assertNotIn(result["status"], {"ok", "accepted", "go"})

    def test_forged_broker_accepted_status_cannot_satisfy_installed_admission(self):
        result = self._installed({"status": "accepted",
                                  "verifier_uid": acceptance_cli.VERIFIER_UID,
                                  "evaluator_uid": acceptance_cli.VERIFIER_UID + 1})
        self.assertEqual(result["status"], "blocked", result)

    def test_untrusted_broker_claim_cannot_execute_protected_gate(self):
        with patch.object(ipc, "_protected_receipt_at",
                          return_value={"status": "verified_uninstalled"}):
            result = acceptance_gate.run_gate(Path("/tmp/untrusted"),
                    {"gate_id": "g", "contract": "c",
                     "checks": [{"name": "danger", "command": ["sh", "-c", "exit 0"]}]},
                    "a" * 40)
        self.assertEqual(result["status"], "blocked", result)
        self.assertEqual(result["checks"][0]["status"], "blocked")

    def test_uninstalled_broker_cannot_consume_live_admission_receipt(self):
        result = ipc._protected_receipt_at(
            Path("/tmp/unprivileged.sock"), task_id="task-A", context_id="context-A",
            generation="generation-A", broker_verify_key=object(),
            ledger_dir=Path("/tmp/missing-ledger"))
        self.assertEqual(result["status"], "blocked", result)


if __name__ == "__main__":
    unittest.main()
