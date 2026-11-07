#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

from acceptance_keyring import (
    load_signing_key,
    sign_payload,
    verify_against_any_trusted,
    verify_signature,
)

SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=False
    )
    if result.returncode:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def tree_sha(repo: Path) -> str:
    return git(repo, "rev-parse", "HEAD^{tree}")


def commit_sha(repo: Path) -> str:
    return git(repo, "rev-parse", "HEAD")


def tree_hash_of_files(repo: Path, files: list[str]) -> str:
    hasher = hashlib.sha256()
    for rel in sorted(files):
        path = repo / rel
        if not path.is_file():
            raise RuntimeError(f"missing required evidence file: {rel}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        hasher.update(f"{rel}:{digest}\n".encode("utf-8"))
    return hasher.hexdigest()


def build_payload(
    repo: Path,
    *,
    commit: str | None = None,
    files: list[str] | None = None,
    checks: list[dict[str, Any]] | None = None,
    environment: dict[str, str] | None = None,
    notes: str = "",
) -> dict[str, Any]:
    repo = repo.resolve()
    if not (repo / ".git").exists() and not subprocess.run(
        ["git", "-C", str(repo), "rev-parse"], capture_output=True
    ).returncode == 0:
        raise RuntimeError(f"{repo} is not a git checkout")
    if commit is None:
        commit = commit_sha(repo)
    if not SHA_PATTERN.fullmatch(commit):
        raise RuntimeError("commit must be a full 40-character SHA")
    actual = git(repo, "rev-parse", commit)
    if actual != commit:
        raise RuntimeError(f"commit {commit} does not resolve in {repo}")
    tree = tree_sha(repo)
    file_manifest = {}
    for rel in sorted(files or []):
        path = repo / rel
        if not path.is_file():
            raise RuntimeError(f"missing required evidence file: {rel}")
        file_manifest[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return {
        "schema": "orchestra-acceptance-evidence",
        "schema_version": 1,
        "commit": commit,
        "tree": tree,
        "files": file_manifest,
        "checks": checks or [],
        "environment": environment or {},
        "notes": notes,
    }


def sign(payload: dict[str, Any], key_path: Path) -> dict[str, Any]:
    key = load_signing_key(key_path)
    signature = sign_payload(payload, key)
    return {
        "payload": payload,
        "signature": signature,
        "signing_key": str(Path(key_path).resolve()),
        "algorithm": "ed25519",
    }


def verify(envelope: dict[str, Any], trusted_keys: list[Any] | None = None, home: Path | None = None) -> dict[str, Any]:
    payload = envelope.get("payload")
    signature = envelope.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, str):
        return {"status": "blocked", "reason": "envelope lacks payload and signature"}
    if not SHA_PATTERN.fullmatch(str(payload.get("commit", ""))):
        return {"status": "blocked", "reason": "payload commit is not a full SHA"}
    if trusted_keys:
        ok = any(verify_signature(payload, signature, key) for key in trusted_keys)
    else:
        ok = verify_against_any_trusted(payload, signature, home=home)
    if not ok:
        return {"status": "blocked", "reason": "signature not valid for any trusted verifier key"}
    return {"status": "ok", "commit": payload["commit"], "tree": payload.get("tree")}


def load_envelope(path: Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_envelope(path: Path, envelope: dict[str, Any]) -> Path:
    Path(path).write_text(
        json.dumps(envelope, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    return path
