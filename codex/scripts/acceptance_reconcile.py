from __future__ import annotations

import argparse
import json
import os
import time
import fcntl
from pathlib import Path
from typing import Any

from acceptance_keyring import default_home

RECEIPT_NAME = "receipts.jsonl"
STATE_NAME = "launch_state.json"


def store_dir(home: Path | None = None) -> Path:
    target = default_home() if home is None else home
    return target / "reconcile"


def receipt_path(home: Path | None = None) -> Path:
    return store_dir(home) / RECEIPT_NAME


def state_path(home: Path | None = None) -> Path:
    return store_dir(home) / STATE_NAME


def _ensure(home: Path | None = None) -> Path:
    directory = store_dir(home)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _locked_read(path: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    if not path.is_file():
        return entries
    with open(path, "r", encoding="utf-8") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_SH)
        try:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except ValueError:
                    continue
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    return entries


def _locked_write(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            f.write(data)
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def _locked_check_and_write(path: Path, t3_thread_id: str, receipt: str, entry: dict[str, Any]) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a+", encoding="utf-8") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            f.seek(0)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    existing = json.loads(line)
                    if (existing.get("t3_thread_id") == t3_thread_id
                        and existing.get("receipt") == receipt):
                        replayed = {key: value for key, value in existing.items() if key != "status"}
                        return {"status": "duplicate", **replayed}
                except ValueError:
                    continue
            f.write(json.dumps(entry, sort_keys=True) + "\n")
            return {"status": "recorded", **entry}
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def record_launch(
    *,
    t3_thread_id: str,
    receipt: str,
    task_id: str,
    phase: str,
    commit: str,
    worktree: str | None = None,
    home: Path | None = None,
) -> dict[str, Any]:
    if not t3_thread_id or not isinstance(t3_thread_id, str):
        return {"status": "blocked", "reason": "t3_thread_id is required"}
    if not receipt or not isinstance(receipt, str):
        return {"status": "blocked", "reason": "receipt is required"}
    if not commit or len(commit) != 40:
        return {"status": "blocked", "reason": "commit must be a full SHA"}
    _ensure(home)
    entry = {
        "t3_thread_id": t3_thread_id,
        "receipt": receipt,
        "task_id": task_id,
        "phase": phase,
        "commit": commit,
        "worktree": worktree,
        "recorded_at": time.time(),
    }
    return _locked_check_and_write(receipt_path(home), t3_thread_id, receipt, entry)


def lookup(
    t3_thread_id: str, receipt: str, *, home: Path | None = None
) -> dict[str, Any]:
    entries = _locked_read(receipt_path(home))
    for entry in entries:
        if (
            entry.get("t3_thread_id") == t3_thread_id
            and entry.get("receipt") == receipt
        ):
            return {"status": "found", **entry}
    return {"status": "unknown", "t3_thread_id": t3_thread_id, "receipt": receipt}


def reconcile(
    t3_thread_id: str,
    receipt: str,
    *,
    home: Path | None = None,
) -> dict[str, Any]:
    found = lookup(t3_thread_id, receipt, home=home)
    if found["status"] == "found":
        replayed = {key: value for key, value in found.items() if key != "status"}
        return {"status": "replayed", "reason": "duplicate T3 launch replayed from receipt", **replayed}
    return {
        "status": "blocked",
        "reason": "unknown T3 launch; refusing to start a duplicate scheduler run",
        "t3_thread_id": t3_thread_id,
        "receipt": receipt,
    }


def list_launches(*, home: Path | None = None) -> list[dict[str, Any]]:
    return _locked_read(receipt_path(home))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, default=default_home())
    sub = parser.add_subparsers(dest="action", required=True)
    record = sub.add_parser("record")
    record.add_argument("--t3-thread-id", required=True)
    record.add_argument("--receipt", required=True)
    record.add_argument("--task-id", required=True)
    record.add_argument("--phase", required=True)
    record.add_argument("--commit", required=True)
    record.add_argument("--worktree", default=None)
    look = sub.add_parser("lookup")
    look.add_argument("--t3-thread-id", required=True)
    look.add_argument("--receipt", required=True)
    rec = sub.add_parser("reconcile")
    rec.add_argument("--t3-thread-id", required=True)
    rec.add_argument("--receipt", required=True)
    sub.add_parser("list")
    args = parser.parse_args()
    if args.action == "record":
        result = record_launch(
            t3_thread_id=args.t3_thread_id,
            receipt=args.receipt,
            task_id=args.task_id,
            phase=args.phase,
            commit=args.commit,
            worktree=args.worktree,
            home=args.home,
        )
    elif args.action == "lookup":
        result = lookup(args.t3_thread_id, args.receipt, home=args.home)
    elif args.action == "reconcile":
        result = reconcile(args.t3_thread_id, args.receipt, home=args.home)
    else:
        result = {"status": "ok", "launches": list_launches(home=args.home)}
    print(json.dumps(result, sort_keys=True))
    return 1 if result["status"] in {"blocked", "unknown"} else 0


if __name__ == "__main__":
    raise SystemExit(main())
