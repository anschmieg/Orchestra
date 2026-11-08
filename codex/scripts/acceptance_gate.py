from __future__ import annotations

import argparse
import json
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
UNISOLATED_EVALUATOR_REASON = (
    "untrusted evaluator execution disabled: no installed, verified "
    "OS-principal isolation broker"
)


def gate_spec_path(repo: Path) -> Path:
    return repo / ".orchestra-acceptance" / GATE_SPEC_NAME


def load_gate_spec(path: Path) -> dict[str, Any] | None:
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


def run_check(repo: Path, check: dict[str, Any], timeout: int = 300) -> dict[str, Any]:
    """Never invoke arbitrary evaluator commands in the verifier process."""
    return {
        "name": check["name"],
        "status": "blocked",
        "reason": UNISOLATED_EVALUATOR_REASON,
    }


def run_gate(repo: Path, spec: dict[str, Any], commit: str) -> dict[str, Any]:
    """No evaluator may run until a privileged isolation broker is implemented.

    An environment variable, chmod, unprivileged container, or read-only
    checkout cannot establish the required separate OS principal. There is
    intentionally no configurable bypass or same-UID fallback here.
    """
    return {
        "status": "blocked",
        "gate_id": spec["gate_id"],
        "contract": spec["contract"],
        "checks": [run_check(repo, check) for check in spec["checks"]],
        "reason": UNISOLATED_EVALUATOR_REASON,
    }


def evaluate(
    repo: Path,
    envelope: dict[str, Any],
    *,
    gate_spec: dict[str, Any] | None = None,
    trusted_keys: list[Any] | None = None,
    home: Path | None = None,
    expected_commit: str | None = None,
) -> dict[str, Any]:
    repo = repo.resolve()
    signature_result = verify(envelope, trusted_keys) if trusted_keys else verify(envelope, home=home)
    if signature_result["status"] != "ok":
        return signature_result
    commit = signature_result["commit"]
    payload = envelope.get("payload", {})
    expected_tree = payload.get("tree")
    actual_commit = commit_sha(repo)
    actual_tree = tree_sha(repo)
    if expected_commit is not None and commit != expected_commit:
        return {
            "status": "blocked",
            "reason": "signed commit does not match expected commit",
            "commit": commit,
            "expected_commit": expected_commit,
        }
    if commit != actual_commit:
        return {
            "status": "blocked",
            "reason": "signed commit does not match checkout HEAD commit",
            "signed_commit": commit,
            "checkout_commit": actual_commit,
        }
    if expected_tree and expected_tree != actual_tree:
        return {
            "status": "blocked",
            "reason": "evidence tree does not match the checked-out commit tree",
            "commit": commit,
            "expected_tree": expected_tree,
            "actual_tree": actual_tree,
        }
    if gate_spec is None:
        return {
            "status": "blocked",
            "reason": "gate spec must be provided by the verifier; no spec found",
            "commit": commit,
        }
    error = validate_gate_spec(gate_spec)
    if error:
        return {"status": "blocked", "reason": error, "commit": commit}
    gate_result = run_gate(repo, gate_spec, commit)
    gate_result["commit"] = commit
    gate_result["tree"] = actual_tree
    return gate_result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--home", type=Path, default=default_home())
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--write", type=Path, default=None)
    args = parser.parse_args()

    repo = args.repo.resolve()
    envelope = load_envelope(args.evidence)
    trusted = trusted_verify_keys(args.home)
    spec = load_gate_spec(args.spec)
    if spec is None:
        result = {"status": "blocked", "reason": "could not load gate spec from verifier-provided path"}
        print(json.dumps(result, sort_keys=True, indent=2))
        return 1
    result = evaluate(repo, envelope, gate_spec=spec, trusted_keys=trusted or None, home=args.home)
    output = json.dumps(result, sort_keys=True, indent=2)
    print(output)
    if args.write is not None:
        args.write.parent.mkdir(parents=True, exist_ok=True)
        args.write.write_text(output + "\n", encoding="utf-8")
    return 1 if result["status"] not in {"ok", "accepted"} else 0


if __name__ == "__main__":
    raise SystemExit(main())
