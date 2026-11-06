#!/usr/bin/env python3
"""Explicit permission boundaries for trustworthy acceptance.

Boundaries are declared, checked and fail-closed. An operation that crosses a
boundary without the matching grant is blocked before it runs, so unknown or
ambiguous states never silently proceed.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

GRANT_ENV = "ORCHESTRA_ACCEPTANCE_GRANT"
VALID_GRANTS = {
    "sign_evidence",
    "verify_evidence",
    "run_gate",
    "record_launch",
    "reconcile_launch",
    "manage_keyring",
    "create_worktree",
    "commit_phase",
    "deliver",
}

MUTATING = {
    "sign_evidence",
    "record_launch",
    "manage_keyring",
    "create_worktree",
    "commit_phase",
    "deliver",
}


def active_grants() -> set[str]:
    raw = os.environ.get(GRANT_ENV, "")
    grants: set[str] = set()
    for token in raw.split(","):
        token = token.strip()
        if token in VALID_GRANTS:
            grants.add(token)
    return grants


def require(grant: str) -> dict[str, Any]:
    if grant not in VALID_GRANTS:
        return {"status": "blocked", "reason": f"unknown grant: {grant}"}
    if grant in active_grants():
        return {"status": "ok", "grant": grant}
    return {
        "status": "blocked",
        "reason": f"missing grant {grant}; set {GRANT_ENV}",
        "grant": grant,
    }


def boundary_check(
    *,
    grant: str,
    repo: Path | None = None,
    paths: list[Path] | None = None,
    network: bool = False,
) -> dict[str, Any]:
    result = require(grant)
    if result["status"] != "ok":
        return result
    if network and grant not in {"deliver"}:
        return {
            "status": "blocked",
            "reason": f"grant {grant} does not authorize network access",
        }
    if repo is not None:
        try:
            resolved = repo.resolve()
        except OSError as error:
            return {"status": "blocked", "reason": f"repo path unsafe: {error}"}
        if not resolved.is_dir():
            return {"status": "blocked", "reason": "repo path is not a directory"}
    for path in paths or []:
        try:
            resolved = path.resolve()
        except OSError as error:
            return {"status": "blocked", "reason": f"path unsafe: {error}"}
        if resolved.is_symlink():
            return {"status": "blocked", "reason": f"path is a symlink: {path}"}
    return result


def git_identity(repo: Path) -> dict[str, str] | None:
    result = subprocess.run(
        ["git", "-C", str(repo), "config", "user.name"],
        capture_output=True, text=True, check=False,
    )
    email = subprocess.run(
        ["git", "-C", str(repo), "config", "user.email"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode or email.returncode:
        return None
    name = result.stdout.strip()
    addr = email.stdout.strip()
    if not name or not addr or "@" not in addr:
        return None
    return {"name": name, "email": addr}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--grant", required=True, choices=sorted(VALID_GRANTS))
    parser.add_argument("--repo", type=Path, default=None)
    parser.add_argument("--network", action="store_true")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    if args.list:
        print(json.dumps({"grants": sorted(VALID_GRANTS), "active": sorted(active_grants())}))
        return 0
    result = boundary_check(
        grant=args.grant, repo=args.repo, network=args.network
    )
    print(json.dumps(result, sort_keys=True))
    return 1 if result["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
