"""One-use signed broker receipt *screening*, not installed-protected admission.

No public-key argument or rootless test can authenticate the privileged launcher.
A successful check deliberately returns verified_uninstalled, never accepted.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import select
import stat
import time
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = 3
MAX_TTL_NS = 5_000_000_000
MAX_LEDGER_BYTES = 16 * 1024 * 1024
CHALLENGE_FIELDS = frozenset({
    "nonce", "task_id", "context_id", "generation",
    "issued_monotonic_ns", "expires_monotonic_ns",
    "verifier_pid", "verifier_uid", "verifier_euid", "verifier_executable",
})
EVALUATOR_FIELDS = frozenset({"evaluator_pid", "evaluator_uid", "evaluator_executable"})
RECEIPT_FIELDS = CHALLENGE_FIELDS | EVALUATOR_FIELDS | {
    "protocol", "operation", "signature",
}
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX128 = re.compile(r"[0-9a-f]{128}\Z")


def _blocked(reason: str) -> dict[str, str]:
    return {"status": "blocked", "reason": reason}


def _executable_identity(path: str) -> list[int]:
    """Stat the *open executable*, not a caller-supplied pathname snapshot."""
    if not hasattr(os, "O_PATH"):
        raise OSError("kernel executable descriptor pinning unavailable")
    descriptor = os.open(path, os.O_PATH | os.O_CLOEXEC)
    try:
        observed = os.fstat(descriptor)
        if not stat.S_ISREG(observed.st_mode):
            raise ValueError("executable descriptor does not refer to a regular file")
        return [observed.st_dev, observed.st_ino, observed.st_mode, observed.st_uid]
    finally:
        os.close(descriptor)


def observe_evaluator(pid: int) -> dict[str, Any]:
    """Observe real/effective UID and executable of a live, PIDFD-pinned process."""
    if type(pid) is not int or pid <= 1 or not hasattr(os, "pidfd_open"):
        raise ValueError("invalid evaluator PID or unavailable kernel pidfd")
    descriptor = os.pidfd_open(pid, 0)
    try:
        with open(f"/proc/self/fdinfo/{descriptor}", encoding="ascii") as source:
            owner_pids = [line.partition(":")[2].strip() for line in source
                          if line.startswith("Pid:")]
        if owner_pids != [str(pid)]:
            raise ValueError("evaluator PIDFD does not match requested PID")
        watcher = select.poll()
        watcher.register(descriptor, select.POLLIN | select.POLLHUP | select.POLLERR)
        if watcher.poll(0):
            raise ValueError("evaluator exited before kernel observation")
        with open(f"/proc/{pid}/status", encoding="ascii") as source:
            uid_lines = [line.split() for line in source if line.startswith("Uid:")]
        if len(uid_lines) != 1 or len(uid_lines[0]) != 5:
            raise ValueError("evaluator kernel UID record unavailable")
        _label, real, effective, _saved, _fs = uid_lines[0]
        executable = _executable_identity(f"/proc/{pid}/exe")
        if watcher.poll(0):
            raise ValueError("evaluator exited during kernel observation")
        return {
            "pid": pid, "uid": int(real), "euid": int(effective),
            "executable": executable,
        }
    finally:
        os.close(descriptor)


def _consume_once(ledger_dir: Path, nonce: str) -> dict[str, str]:
    """Durably consume a nonce before returning. Survives SIGKILL and restarts.

    The caller must ensure the enclosing installation is operator-controlled.
    This helper checks ownership and the direct inode, but is not a trust anchor.
    """
    if type(nonce) is not str or not HEX64.fullmatch(nonce):
        return _blocked("invalid signed admission nonce")
    directory_fd = None
    ledger_fd = None
    try:
        directory_fd = os.open(
            ledger_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        directory = os.fstat(directory_fd)
        if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.geteuid()
                or directory.st_mode & 0o077):
            return _blocked("receipt replay directory lacks private verifier ownership")
        ledger_fd = os.open(
            "used-nonces",
            os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=directory_fd)
        record = os.fstat(ledger_fd)
        if (not stat.S_ISREG(record.st_mode) or record.st_uid != os.geteuid()
                or record.st_mode & 0o077 or record.st_nlink != 1):
            return _blocked("receipt replay ledger is not a private, single-link regular file")
        fcntl.flock(ledger_fd, fcntl.LOCK_EX)
        try:
            size = os.fstat(ledger_fd).st_size
            if size > MAX_LEDGER_BYTES:
                return _blocked("receipt replay ledger exceeds validation bound")
            os.lseek(ledger_fd, 0, os.SEEK_SET)
            data = bytearray()
            while len(data) < size:
                part = os.read(ledger_fd, size - len(data))
                if not part:
                    return _blocked("receipt replay ledger truncated while locked")
                data.extend(part)
            try:
                text = data.decode("ascii")
            except UnicodeError:
                return _blocked("receipt replay ledger corrupted")
            if text and not text.endswith("\n"):
                return _blocked("receipt replay ledger contains partial record")
            records = text.splitlines()
            if any(not HEX64.fullmatch(item) for item in records) or len(records) != len(set(records)):
                return _blocked("receipt replay ledger corrupted or ambiguous")
            if nonce in records:
                return _blocked("signed broker receipt replay detected")
            if size + 65 > MAX_LEDGER_BYTES:
                return _blocked("receipt replay ledger full")
            os.lseek(ledger_fd, 0, os.SEEK_END)
            appended = (nonce + "\n").encode("ascii")
            if os.write(ledger_fd, appended) != len(appended):
                return _blocked("receipt replay ledger write incomplete")
            os.fsync(ledger_fd)
            os.fsync(directory_fd)
            return {"status": "recorded"}
        finally:
            fcntl.flock(ledger_fd, fcntl.LOCK_UN)
    except (OSError, ValueError) as error:
        return _blocked(f"receipt replay persistence unavailable: {type(error).__name__}")
    finally:
        if ledger_fd is not None:
            os.close(ledger_fd)
        if directory_fd is not None:
            os.close(directory_fd)


def verify_one_use_receipt(
    receipt: dict[str, Any],
    challenge: dict[str, Any],
    broker_verify_key: Any,
    ledger_dir: Path,
) -> dict[str, str]:
    """Validate signed provenance, kernel identities and durable one-shot use.

    A simulated broker may pass cryptographic unit tests, but cannot grant GO:
    operator-pinned broker keys, launcher, execution and cgroup proof are absent.
    """
    try:
        if type(challenge) is not dict or set(challenge) != CHALLENGE_FIELDS:
            return _blocked("trusted challenge schema mismatch")
        if type(receipt) is not dict or set(receipt) != RECEIPT_FIELDS:
            return _blocked("signed broker receipt schema mismatch")
        if type(receipt["protocol"]) is not int or receipt["protocol"] != PROTOCOL_VERSION:
            return _blocked("signed broker protocol mismatch")
        if receipt["operation"] != "protected-admission":
            return _blocked("signed broker operation mismatch")
        for field in CHALLENGE_FIELDS:
            if type(receipt[field]) is not type(challenge[field]) or receipt[field] != challenge[field]:
                return _blocked(f"signed broker challenge binding mismatch: {field}")
        for name in ("task_id", "context_id", "generation"):
            value = challenge[name]
            if (type(value) is not str or not (0 < len(value) <= 256) or
                    value != value.strip() or any(ord(c) < 32 or ord(c) == 127 for c in value)):
                return _blocked(f"invalid signed broker {name}")
        nonce = challenge["nonce"]
        if type(nonce) is not str or not HEX64.fullmatch(nonce):
            return _blocked("invalid signed broker nonce")
        issued, expires = challenge["issued_monotonic_ns"], challenge["expires_monotonic_ns"]
        if (type(issued) is not int or type(expires) is not int or
                issued <= 0 or expires <= issued or expires - issued > MAX_TTL_NS):
            return _blocked("signed broker receipt expiry invalid")
        now = time.monotonic_ns()
        if not issued <= now < expires:
            return _blocked("signed broker response late, future-dated, or expired")
        signature = receipt["signature"]
        if type(signature) is not str or not HEX128.fullmatch(signature):
            return _blocked("signed broker signature encoding invalid")
        body = {key: value for key, value in receipt.items() if key != "signature"}
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        try:
            broker_verify_key.verify(bytes.fromhex(signature), canonical)
        except (ValueError, TypeError, Exception) as error:
            return _blocked(f"signed broker signature invalid: {type(error).__name__}")

        verifier_pid = receipt["verifier_pid"]
        verifier_uid = receipt["verifier_uid"]
        verifier_euid = receipt["verifier_euid"]
        if (type(verifier_pid) is not int or type(verifier_uid) is not int or
                type(verifier_euid) is not int or
                (verifier_pid, verifier_uid, verifier_euid) !=
                (os.getpid(), os.getuid(), os.geteuid()) or verifier_uid != verifier_euid):
            return _blocked("signed broker verifier kernel UID/PID mismatch")
        if receipt["verifier_executable"] != _executable_identity("/proc/self/exe"):
            return _blocked("signed broker verifier immutable executable mismatch")

        evaluator_pid = receipt["evaluator_pid"]
        evaluator_uid = receipt["evaluator_uid"]
        if (type(evaluator_pid) is not int or type(evaluator_uid) is not int
                or evaluator_uid in (0, verifier_uid) or evaluator_pid in (verifier_pid, 0)):
            return _blocked("signed broker evaluator identity is not an independent principal")
        observed = observe_evaluator(evaluator_pid)
        if (type(observed) is not dict or observed.get("pid") != evaluator_pid
                or observed.get("uid") != evaluator_uid
                or observed.get("euid") != evaluator_uid
                or observed.get("executable") != receipt["evaluator_executable"]):
            return _blocked("signed broker evaluator kernel UID/executable mismatch")
        if time.monotonic_ns() >= expires:
            return _blocked("signed broker receipt expired before consumption")
        consumed = _consume_once(ledger_dir, nonce)
        if consumed["status"] != "recorded":
            return consumed
        observed_after = observe_evaluator(evaluator_pid)
        if observed_after != observed or time.monotonic_ns() >= expires:
            return _blocked("signed broker evaluator changed or expired after nonce consumption")
        return {"status": "verified_uninstalled"}
    except (OSError, ValueError, TypeError, AttributeError, OverflowError) as error:
        return _blocked(f"signed broker admission provenance unavailable: {type(error).__name__}")
