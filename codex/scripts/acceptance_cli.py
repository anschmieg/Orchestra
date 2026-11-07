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

VERIFIER_HOME = Path("/etc/orchestra-acceptance")
VERIFIER_UID = 999


def _verifier_principal_check() -> dict[str, Any]:
    if os.getuid() != VERIFIER_UID:
        return {"status": "blocked", "reason": f"approve requires verifier UID {VERIFIER_UID}, current UID {os.getuid()}"}
    home = VERIFIER_HOME
    if not home.is_dir():
        return {"status": "blocked", "reason": "verifier trust root not found"}
    grants_file = home / "grants.json"
    if not grants_file.is_file():
        return {"status": "blocked", "reason": "verifier grants file not found"}
    stat = grants_file.stat()
    if stat.st_uid != VERIFIER_UID:
        return {"status": "blocked", "reason": "grants file not owned by verifier"}
    if stat.st_mode & 0o077:
        return {"status": "blocked", "reason": "grants file is world/group writable"}
    return {"status": "ok"}


def _run(repo: Path, command: list[str]) -> tuple[int, str, str]:
    process = subprocess.run(
        [sys.executable, str(HERE / command[0]), *command[1:]],
        cwd=str(repo),
        capture_output=True, text=True, check=False,
    )
    return process.returncode, process.stdout, process.stderr


def cmd_start(args: argparse.Namespace) -> int:
    repo = args.repo.resolve()
    grant = require("record_launch", home=args.home)
    if grant["status"] != "ok":
        return _blocked(grant["reason"])
    boundary = boundary_check(grant="record_launch", repo=repo, home=args.home)
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
    principal = _verifier_principal_check()
    if principal["status"] != "ok":
        return _blocked(principal["reason"])
    repo = args.repo.resolve()
    if args.spec.resolve().is_relative_to(repo.resolve()):
        return _blocked("gate spec must come from verifier trust root, not implementer repo")
    if not args.spec.resolve().is_relative_to(VERIFIER_HOME.resolve()):
        return _blocked("gate spec must be in verifier trust root")
    boundary = boundary_check(grant="verify_evidence", repo=repo, home=VERIFIER_HOME)
    if boundary["status"] == "blocked":
        return _blocked(boundary["reason"])
    if not args.evidence.is_file():
        return _blocked(f"evidence file not found: {args.evidence}")
    if not args.spec.is_file():
        return _blocked(f"gate spec not found: {args.spec}")
    if not args.evidence.parent.is_dir():
        return _blocked("evidence must live in a directory")
    if not args.report.resolve().parent.is_relative_to(VERIFIER_HOME.resolve()):
        return _blocked("report must be written to verifier trust root")
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
            str(VERIFIER_HOME),
            "--write",
            str(args.report),
        ],
    )
    sys.stdout.write(stdout)
    if stderr:
        sys.stderr.write(stderr)
    return code


def cmd_enroll(args: argparse.Namespace) -> int:
    boundary = boundary_check(grant="manage_keyring", repo=None)
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
