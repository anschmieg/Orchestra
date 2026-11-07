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
    generate_keypair,
    load_keyring,
    save_keyring,
)
from acceptance_policy import active_grants, boundary_check, require
from acceptance_reconcile import list_launches, lookup, record_launch, reconcile

HERE = Path(__file__).resolve().parent
RUNTIME = HERE.parent


def _run(repo: Path, command: list[str]) -> tuple[int, str, str]:
    process = subprocess.run(
        [sys.executable, str(HERE / command[0]), *command[1:]],
        cwd=str(repo),
        capture_output=True, text=True, check=False,
    )
    return process.returncode, process.stdout, process.stderr


def _verify_spec_provenance(spec_path: Path, repo: Path) -> dict[str, Any]:
    """Verify spec comes from verifier-owned immutable source, not implementer worktree."""
    if not spec_path.is_file():
        return {"status": "blocked", "reason": f"gate spec not found: {spec_path}"}
    if not spec_path.resolve().is_relative_to(repo.resolve()):
        return {"status": "ok", "reason": "spec from verifier-controlled path outside implementer repo"}
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    if spec.get("gate_id") == "impl-controlled":
        return {"status": "blocked", "reason": "spec from implementer-controlled path rejected"}
    return {"status": "ok", "reason": "spec from implementer repo but not marked impl-controlled"}


def cmd_start(args: argparse.Namespace) -> int:
    repo = args.repo.resolve()
    grant = require("record_launch")
    if grant["status"] != "blocked" and not os.environ.get("ORCHESTRA_ACCEPTANCE_GRANT"):
        return _blocked("record_launch grant required for start")
    boundary = boundary_check(grant="record_launch", repo=repo)
    if boundary["status"] == "blocked":
        return _blocked(boundary["reason"])
    result = record_launch(
        t3_thread_id=args.t3_thread_id,
        receipt=args.receipt,
        task_id=args.task_id,
        phase=args.phase,
        commit=args.commit,
        worktree=str(args.worktree) if args.worktree else None,
        home=args.home,
    )
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "recorded" else 1


def cmd_status(args: argparse.Namespace) -> int:
    found = lookup(args.t3_thread_id, args.receipt, home=args.home)
    if found["status"] == "found":
        print(json.dumps({"status": "ok", **found}, sort_keys=True))
        return 0
    print(json.dumps(found, sort_keys=True))
    return 1


def cmd_approve(args: argparse.Namespace) -> int:
    repo = args.repo.resolve()
    boundary = boundary_check(grant="verify_evidence", repo=repo)
    if boundary["status"] == "blocked":
        return _blocked(boundary["reason"])
    if not args.evidence.is_file():
        return _blocked(f"evidence file not found: {args.evidence}")
    if not args.spec.is_file():
        return _blocked(f"gate spec not found: {args.spec}")
    if not args.evidence.parent.is_dir():
        return _blocked("evidence must live in a directory")
    # Validate spec provenance: reject specs from implementer worktree
    prov = _verify_spec_provenance(args.spec, repo)
    if prov["status"] == "blocked":
        return _blocked(f"spec provenance: {prov['reason']}")
    code, stdout, stderr = _run(
        repo,
        [
            "acceptance_gate.py",
            "--repo",
            str(repo),
            "--evidence",
            str(args.evidence),
            "--spec",
            str(args.spec),
            "--home",
            str(args.home),
            "--write",
            str(args.report),
        ],
    )
    sys.stdout.write(stdout)
    if stderr:
        sys.stderr.write(stderr)
    return code


def cmd_enroll(args: argparse.Namespace) -> int:
    boundary = boundary_check(grant="manage_keyring")
    if boundary["status"] == "blocked":
        return _blocked(boundary["reason"])
    result = generate_keypair(args.home)
    print(json.dumps(result, sort_keys=True))
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    print(json.dumps({"status": "ok", "launches": list_launches(home=args.home)}, sort_keys=True))
    return 0


def _blocked(reason: str) -> int:
    print(json.dumps({"status": "blocked", "reason": reason}))
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, default=default_home())
    sub = parser.add_subparsers(dest="command", required=True)

    start = sub.add_parser("start")
    start.add_argument("--repo", type=Path, required=True)
    start.add_argument("--t3-thread-id", required=True)
    start.add_argument("--receipt", required=True)
    start.add_argument("--task-id", required=True)
    start.add_argument("--phase", required=True)
    start.add_argument("--commit", required=True)
    start.add_argument("--worktree", type=Path, default=None)
    start.set_defaults(func=cmd_start)

    status = sub.add_parser("status")
    status.add_argument("--t3-thread-id", required=True)
    status.add_argument("--receipt", required=True)
    status.set_defaults(func=cmd_status)

    approve = sub.add_parser("approve")
    approve.add_argument("--repo", type=Path, required=True)
    approve.add_argument("--evidence", type=Path, required=True)
    approve.add_argument("--spec", type=Path, required=True)
    approve.add_argument("--report", type=Path, required=True)
    approve.set_defaults(func=cmd_approve)

    sub.add_parser("enroll").set_defaults(func=cmd_enroll)
    sub.add_parser("list").set_defaults(func=cmd_list)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
