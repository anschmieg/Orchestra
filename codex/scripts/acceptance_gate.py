#!/usr/bin/env python3
"""Trustworthy acceptance gate for the Orchestra fork.

A gate is a fail-closed decision over a signed evidence envelope tied to a
commit. It is the smallest trustworthy acceptance extension: the implementer
knows the behavioral contract but never the hidden evaluator tests or rubric,
and a verifier running an immutable commit SHA in a separate boundary can
reject a self-claimed pass because only its key can sign.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from acceptance_keyring import (
    default_home,
    load_keyring,
    trusted_verify_keys,
    verify_against_any_trusted,
)
from acceptance_evidence import (
    build_payload,
    commit_sha,
    git,
    load_envelope,
    tree_sha,
    verify,
)

HERE = Path(__file__).resolve().parent
GATE_SPEC_NAME = "gate.json"


def gate_spec_path(repo: Path) -> Path:
    return repo / ".orchestra-acceptance" / GATE_SPEC_NAME


def load_gate_spec(repo: Path) -> dict[str, Any] | None:
    path = gate_spec_path(repo)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def validate_gate_spec(spec: dict[str, Any]) -> str | None:
    if not isinstance(spec, dict):
        return "gate spec must be a JSON object"
    if set(spec) != {"gate_id", "contract", "checks"}:
        return "gate spec must contain only gate_id, contract and checks"
    gate_id = spec.get("gate_id")
    contract = spec.get("contract")
    checks = spec.get("checks")
    if not isinstance(gate_id, str) or not gate_id.strip():
        return "gate_id must be a nonempty string"
    if not isinstance(contract, str) or not contract.strip():
        return "contract must be a nonempty string"
    if not isinstance(checks, list) or not checks:
        return "checks must be a nonempty list"
    for index, check in enumerate(checks, start=1):
        if not isinstance(check, dict) or set(check) != {"name", "command"}:
            return f"check {index} must contain only name and command"
        name = check.get("name")
        command = check.get("command")
        if not isinstance(name, str) or not name.strip():
            return f"check {index} needs a nonempty name"
        if (
            not isinstance(command, list)
            or not command
            or not all(isinstance(a, str) and a for a in command)
        ):
            return f"check {name} needs a nonempty argv command"
    return None


def run_check(repo: Path, check: dict[str, Any]) -> dict[str, Any]:
    name = check["name"]
    command = list(check["command"])
    try:
        result = subprocess.run(
            command, cwd=str(repo), check=False, capture_output=True, text=True
        )
    except OSError as error:
        return {"name": name, "status": "blocked", "reason": f"could not start: {error}"}
    if result.returncode == 0:
        return {"name": name, "status": "passed", "exit": 0}
    detail = (result.stderr or result.stdout or "no output").strip()[:400]
    return {
        "name": name,
        "status": "failed",
        "exit": result.returncode,
        "detail": detail,
    }


def run_gate(repo: Path, spec: dict[str, Any]) -> dict[str, Any]:
    repo = repo.resolve()
    results = [run_check(repo, check) for check in spec["checks"]]
    failed = [r for r in results if r["status"] == "failed"]
    blocked = [r for r in results if r["status"] == "blocked"]
    if blocked:
        return {
            "status": "blocked",
            "gate_id": spec["gate_id"],
            "contract": spec["contract"],
            "checks": results,
            "reason": "a check could not run",
        }
    if failed:
        return {
            "status": "rejected",
            "gate_id": spec["gate_id"],
            "contract": spec["contract"],
            "checks": results,
            "reason": "at least one check failed",
        }
    return {
        "status": "accepted",
        "gate_id": spec["gate_id"],
        "contract": spec["contract"],
        "checks": results,
    }


def evaluate(
    repo: Path,
    envelope: dict[str, Any],
    *,
    trusted_keys: list[Any] | None = None,
    home: Path | None = None,
) -> dict[str, Any]:
    repo = repo.resolve()
    signature_result = verify(envelope, trusted_keys) if trusted_keys else verify(envelope, home=home)
    if signature_result["status"] != "ok":
        return signature_result
    commit = signature_result["commit"]
    spec = load_gate_spec(repo)
    if spec is None:
        return {
            "status": "blocked",
            "reason": "no .orchestra-acceptance/gate.json contract found at the evidence commit",
            "commit": commit,
        }
    error = validate_gate_spec(spec)
    if error:
        return {"status": "blocked", "reason": error, "commit": commit}
    payload = envelope.get("payload", {})
    expected_tree = payload.get("tree")
    actual_tree = tree_sha(repo)
    if expected_tree and expected_tree != actual_tree:
        return {
            "status": "blocked",
            "reason": "evidence tree does not match the checked-out commit tree",
            "commit": commit,
            "expected_tree": expected_tree,
            "actual_tree": actual_tree,
        }
    gate_result = run_gate(repo, spec)
    gate_result["commit"] = commit
    gate_result["tree"] = actual_tree
    return gate_result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--home", type=Path, default=default_home())
    parser.add_argument("--write", type=Path, default=None)
    args = parser.parse_args()

    repo = args.repo.resolve()
    envelope = load_envelope(args.evidence)
    trusted = trusted_verify_keys(args.home)
    result = evaluate(repo, envelope, trusted_keys=trusted or None)
    output = json.dumps(result, sort_keys=True, indent=2)
    print(output)
    if args.write is not None:
        args.write.parent.mkdir(parents=True, exist_ok=True)
        args.write.write_text(output + "\n", encoding="utf-8")
    return 1 if result["status"] not in {"ok", "accepted"} else 0


if __name__ == "__main__":
    raise SystemExit(main())
