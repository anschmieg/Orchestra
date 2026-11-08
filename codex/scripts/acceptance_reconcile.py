from __future__ import annotations

import argparse
import json
import math
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


def _no_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate receipt ledger JSON key")
        result[key] = value
    return result


def _read_validated_entries(lines: Any) -> list[dict[str, Any]]:
    """Reject ambiguous or torn ledger history, including after a matching receipt."""
    entries: list[dict[str, Any]] = []
    receipts: set[str] = set()
    required = {"t3_thread_id", "receipt", "task_id", "phase", "commit", "worktree", "recorded_at"}
    for line in lines:
        if not line.strip():
            continue
        try:
            entry = json.loads(line, object_pairs_hook=_no_duplicate_json_keys)
        except ValueError as error:
            raise ValueError("corrupt receipt ledger") from error
        if not isinstance(entry, dict) or set(entry) != required:
            raise ValueError("corrupt receipt ledger")
        if _invalid_identity(*(entry[field] for field in
                ("t3_thread_id", "receipt", "task_id", "phase", "commit", "worktree"))):
            raise ValueError("corrupt receipt ledger")
        recorded_at = entry["recorded_at"]
        try:
            valid_timestamp = (
                not isinstance(recorded_at, bool)
                and isinstance(recorded_at, (int, float))
                and math.isfinite(recorded_at) and recorded_at > 0
            )
        except OverflowError:
            valid_timestamp = False
        if not valid_timestamp:
            raise ValueError("corrupt receipt ledger")
        if entry["receipt"] in receipts:
            raise ValueError("ambiguous duplicate receipt ledger")
        receipts.add(entry["receipt"])
        entries.append(entry)
    return entries


def _locked_read(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    with open(path, "r", encoding="utf-8") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_SH)
        try:
            return _read_validated_entries(f)
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)


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
            try:
                existing_entries = _read_validated_entries(f)
            except ValueError:
                return {"status": "blocked", "reason": "receipt ledger corrupt or ambiguous"}
            for existing in existing_entries:
                if existing["receipt"] == receipt:
                    if existing["t3_thread_id"] != t3_thread_id:
                        return {"status": "blocked", "reason": "receipt belongs to another thread"}
                    if any(existing[field] != entry[field]
                           for field in ("task_id", "phase", "commit", "worktree")):
                        return {"status": "blocked", "reason": "receipt context mismatch"}
                    return {"status": "duplicate", **existing}
            f.write(json.dumps(entry, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
            return {"status": "recorded", **entry}
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def _invalid_identity(
    t3_thread_id: str, receipt: str, task_id: str, phase: str,
    commit: str, worktree: str | None,
) -> str | None:
    for field, value in (
        ("t3_thread_id", t3_thread_id), ("receipt", receipt),
        ("task_id", task_id), ("phase", phase),
    ):
        if (
            not isinstance(value, str) or not value or value != value.strip()
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
        ):
            return f"{field} must be a nonempty canonical identifier"
    if not isinstance(commit, str) or len(commit) != 40 or any(
        digit not in "0123456789abcdefABCDEF" for digit in commit
    ):
        return "commit must be a full hexadecimal SHA"
    if (
        not isinstance(worktree, str) or not worktree or worktree != worktree.strip()
        or any(ord(char) < 32 or ord(char) == 127 for char in worktree)
        or not Path(worktree).is_absolute() or worktree == "/"
        or os.path.normpath(worktree) != worktree
    ):
        return "worktree must be a canonical absolute non-root path"
    return None


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
    error = _invalid_identity(t3_thread_id, receipt, task_id, phase, commit, worktree)
    if error:
        return {"status": "blocked", "reason": error}
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
    try:
        entries = _locked_read(receipt_path(home))
    except (OSError, ValueError):
        return {"status": "blocked", "reason": "receipt ledger unreadable or corrupt"}
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
    task_id: str | None = None,
    phase: str | None = None,
    commit: str | None = None,
    worktree: str | None = None,
    home: Path | None = None,
) -> dict[str, Any]:
    found = lookup(t3_thread_id, receipt, home=home)
    if found["status"] == "blocked":
        return found
    if found["status"] == "found":
        error = _invalid_identity(t3_thread_id, receipt, task_id, phase, commit, worktree)
        if error:
            return {"status": "blocked", "reason": error}
        expected = {"task_id": task_id, "phase": phase, "commit": commit, "worktree": worktree}
        if any(found.get(field) != value for field, value in expected.items()):
            return {"status": "blocked", "reason": "receipt context mismatch"}
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
    rec.add_argument("--task-id", required=True)
    rec.add_argument("--phase", required=True)
    rec.add_argument("--commit", required=True)
    rec.add_argument("--worktree", required=True)
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
        result = reconcile(
            args.t3_thread_id, args.receipt, task_id=args.task_id,
            phase=args.phase, commit=args.commit, worktree=args.worktree, home=args.home,
        )
    else:
        result = {"status": "ok", "launches": list_launches(home=args.home)}
    print(json.dumps(result, sort_keys=True))
    return 1 if result["status"] in {"blocked", "unknown"} else 0


if __name__ == "__main__":
    raise SystemExit(main())
