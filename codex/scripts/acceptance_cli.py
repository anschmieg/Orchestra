from __future__ import annotations

import argparse
import json
import os
import stat
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
from acceptance_broker_ipc import (
    BROKER_SOCKET, _endpoint_identity, _protected_receipt_at, probe_broker,
)
from acceptance_keyring import load_verify_key
from acceptance_reconcile import list_launches, lookup, record_launch, reconcile

HERE = Path(__file__).resolve().parent
RUNTIME = HERE.parent

VERIFIER_HOME = Path("/etc/orchestra-acceptance")
VERIFIER_UID = 999
BROKER_INSTALLATION = Path("/etc/orchestra-acceptance/broker-installation.json")
BROKER_LEDGER = Path("/etc/orchestra-acceptance/admissions")



def _protected_path(path: Path, *, label: str, owners: tuple[int, ...]) -> str | None:
    if not path.is_absolute() or ".." in path.parts:
        return f"{label} must use an absolute unambiguous installation path"
    required_flags = ("O_PATH", "O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")
    if any(not hasattr(os, name) for name in required_flags):
        return f"{label} descriptor-based installation verification is unavailable"
    opened = []
    current = Path("/")
    parent_fd = None
    try:
        components = path.parts[1:]
        for index, component in enumerate(("", *components)):
            if index:
                current = current / component
            is_leaf = index == len(components)
            segment = "leaf" if is_leaf else "ancestor"
            try:
                snapshot = os.lstat(current)
            except OSError:
                return f"{label} installation path not found: {current}"
            if snapshot.st_uid not in owners or snapshot.st_mode & 0o022:
                return f"{label} {segment} is not protected: {current}"
            if is_leaf:
                valid = (stat.S_ISDIR(snapshot.st_mode) if label == "verifier trust root"
                         else stat.S_ISREG(snapshot.st_mode))
                if not valid:
                    return f"{label} leaf must be a protected regular file or trust directory: {current}"
            elif not stat.S_ISDIR(snapshot.st_mode):
                return f"{label} ancestor must be a real directory: {current}"
            flags = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
            if not is_leaf:
                flags |= os.O_DIRECTORY
            try:
                if index:
                    fd = os.open(component, flags, dir_fd=parent_fd)
                else:
                    fd = os.open("/", flags)
            except OSError:
                return f"{label} {segment} descriptor open failed: {current}"
            opened.append((current, fd))
            pinned = os.fstat(fd)
            identity = lambda st: (st.st_dev, st.st_ino, st.st_mode, st.st_uid)
            try:
                same = identity(snapshot) == identity(pinned)
            except AttributeError:
                same = False
            if not same:
                return f"{label} {segment} changed during descriptor verification: {current}"
            parent_fd = fd
        for checked_path, fd in opened:
            try:
                observed = os.lstat(checked_path)
                pinned = os.fstat(fd)
            except OSError:
                return f"{label} path disappeared during descriptor verification: {checked_path}"
            if identity(observed) != identity(pinned):
                return f"{label} path changed after descriptor pinning: {checked_path}"
        return None
    finally:
        for _, fd in reversed(opened):
            os.close(fd)



def _load_operator_installation() -> dict[str, Any]:
    violation = _protected_path(
        BROKER_INSTALLATION, label="broker installation manifest", owners=(0,))
    if violation:
        return {"status": "blocked", "reason": violation}
    descriptor = None
    try:
        descriptor = os.open(
            BROKER_INSTALLATION, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        pinned = os.fstat(descriptor)
        if (not stat.S_ISREG(pinned.st_mode) or pinned.st_uid != 0
                or pinned.st_mode & 0o022 or pinned.st_nlink != 1
                or pinned.st_size < 2 or pinned.st_size > 8192):
            return {"status": "blocked",
                    "reason": "broker installation manifest is not a protected single-link root file"}
        raw = os.read(descriptor, 8193)
        observed = os.lstat(BROKER_INSTALLATION)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_uid, item.st_mode)
        if (len(raw) != pinned.st_size or identity(observed) != identity(pinned)):
            return {"status": "blocked",
                    "reason": "broker installation manifest changed during descriptor read"}
        def strict_pairs(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("ambiguous duplicate installation field")
                value[key] = item
            return value
        manifest = json.loads(raw.decode("utf-8"), object_pairs_hook=strict_pairs)
    except (OSError, ValueError, UnicodeError, TypeError) as error:
        return {"status": "blocked",
                "reason": f"broker installation provenance invalid: {type(error).__name__}"}
    finally:
        if descriptor is not None:
            os.close(descriptor)

    fields = {
        "schema", "installation_id", "generation", "task_id", "context_id",
        "broker_socket", "broker_uid", "broker_executable", "socket_identity",
        "verifier_uid", "evaluator_uid", "broker_public_key",
    }
    if type(manifest) is not dict or set(manifest) != fields:
        return {"status": "blocked", "reason": "broker installation schema mismatch"}
    for field in ("installation_id", "generation", "task_id", "context_id"):
        value = manifest[field]
        if (type(value) is not str or not (0 < len(value) <= 256)
                or value != value.strip()
                or any(ord(c) < 32 or ord(c) == 127 for c in value)):
            return {"status": "blocked", "reason": f"broker installation {field} invalid"}
    if (type(manifest["schema"]) is not int or manifest["schema"] != 1
            or type(manifest["broker_socket"]) is not str
            or manifest["broker_socket"] != str(BROKER_SOCKET)
            or type(manifest["broker_uid"]) is not int or manifest["broker_uid"] != 0
            or type(manifest["verifier_uid"]) is not int
            or manifest["verifier_uid"] != VERIFIER_UID
            or type(manifest["evaluator_uid"]) is not int
            or manifest["evaluator_uid"] in (0, VERIFIER_UID)
            or manifest["evaluator_uid"] < 1):
        return {"status": "blocked", "reason": "broker installation kernel identity mismatch"}
    executable = manifest["broker_executable"]
    endpoint = manifest["socket_identity"]
    if (type(executable) is not list or len(executable) != 4
            or any(type(value) is not int or value < 0 for value in executable)
            or not stat.S_ISREG(executable[2]) or executable[3] != 0
            or executable[2] & 0o022
            or type(endpoint) is not list or len(endpoint) != 4
            or any(type(value) is not int or value < 0 for value in endpoint)
            or endpoint[2] != 0 or not stat.S_ISSOCK(endpoint[3])
            or endpoint[3] & 0o002):
        return {"status": "blocked", "reason": "broker installation executable or socket identity invalid"}
    key = manifest["broker_public_key"]
    if (type(key) is not str or not key.startswith("ssh-ed25519 ")
            or len(key) > 1024 or "\n" in key or "\r" in key):
        return {"status": "blocked", "reason": "broker installation public key is not pinned Ed25519"}
    try:
        verify_key = load_verify_key(key)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        if not isinstance(verify_key, Ed25519PublicKey):
            raise ValueError("broker key is not Ed25519")
    except (OSError, ValueError, TypeError):
        return {"status": "blocked", "reason": "broker installation public key cannot be verified"}
    return {"status": "ok", "installation": manifest}


def _installed_boundary_snapshot(manifest: dict[str, Any]) -> dict[str, Any]:
    tracked = [
        ("operator manifest", BROKER_INSTALLATION, "broker installation manifest", (0,), False),
        ("socket parent", BROKER_SOCKET.parent, "verifier trust root", (0,), True),
        ("replay ledger", BROKER_LEDGER, "verifier trust root", (0, VERIFIER_UID), True),
        ("verifier trust root", VERIFIER_HOME, "verifier trust root", (0, VERIFIER_UID), True),
        ("verifier grants", VERIFIER_HOME / "grants.json", "verifier grants", (0, VERIFIER_UID), False),
        ("verifier keyring", VERIFIER_HOME / "keyring.json", "verifier keyring", (0, VERIFIER_UID), False),
        ("verifier interpreter", Path(sys.executable), "interpreter", (0,), False),
    ]
    for name in (
        "acceptance_cli.py", "acceptance_gate.py", "acceptance_broker_ipc.py",
        "acceptance_keyring.py", "acceptance_policy.py", "acceptance_reconcile.py",
        "acceptance_evidence.py", "acceptance_receipt.py",
    ):
        tracked.append((f"verifier code {name}", HERE / name, f"verifier code {name}", (0,), False))
    identities = {}
    try:
        for name, path, label, owners, directory in tracked:
            violation = _protected_path(path, label=label, owners=owners)
            if violation:
                return {"status": "blocked", "reason": f"operator installation changed: {violation}"}
            item = os.lstat(path)
            identity = (item.st_dev, item.st_ino, item.st_uid, item.st_gid,
                        item.st_mode, item.st_nlink)
            if not directory:
                identity += (item.st_size, item.st_ctime_ns, item.st_mtime_ns)
            identities[name] = identity
        endpoint = _endpoint_identity(BROKER_SOCKET)
        if tuple(endpoint) != tuple(manifest["socket_identity"]):
            return {"status": "blocked", "reason": "operator installation changed: broker socket identity"}
        identities["broker socket"] = tuple(endpoint)
        identities["kernel process"] = (
            os.getpid(), os.getppid(), os.getuid(), os.geteuid(), os.getgid(), os.getegid())
        cgroup = Path("/proc/self/cgroup").read_bytes()
        if not cgroup:
            return {"status": "blocked", "reason": "operator installation cgroup identity unavailable"}
        identities["kernel cgroup"] = cgroup
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        return {"status": "blocked", "reason":
                f"operator installation identity unavailable: {type(error).__name__}"}
    return {"status": "ok", "identity": identities}


def _installed_verifier_admission_check() -> dict[str, str]:
    if not (sys.flags.isolated and sys.flags.no_site):
        return {"status": "blocked", "reason": "verifier startup requires -I -S before imports"}
    if sys.prefix != sys.base_prefix:
        return {"status": "blocked", "reason": "virtual environment and writable .pth provenance not admitted"}
    code_files = (
        "acceptance_cli.py", "acceptance_gate.py", "acceptance_broker_ipc.py",
        "acceptance_keyring.py", "acceptance_policy.py",
        "acceptance_reconcile.py", "acceptance_evidence.py", "acceptance_receipt.py",
    )
    paths = [("interpreter", Path(sys.executable))]
    paths.extend((f"verifier code {name}", HERE / name) for name in code_files)
    for label, path in paths:
        violation = _protected_path(path, label=label, owners=(0,))
        if violation:
            return {"status": "blocked", "reason": violation}
    installed = _load_operator_installation()
    if installed["status"] != "ok":
        return {"status": "blocked", "reason": "broker attestation missing: " + installed["reason"]}
    manifest = installed["installation"]
    for label, path, owners in (
        ("verifier trust root", BROKER_SOCKET.parent, (0,)),
        ("verifier trust root", BROKER_LEDGER, (0, VERIFIER_UID)),
    ):
        violation = _protected_path(path, label=label, owners=owners)
        if violation:
            return {"status": "blocked", "reason": violation}
    try:
        endpoint = _endpoint_identity(BROKER_SOCKET)
    except OSError:
        return {"status": "blocked", "reason": "pinned broker socket is not installed"}
    if tuple(endpoint) != tuple(manifest["socket_identity"]):
        return {"status": "blocked", "reason": "pinned broker socket installation identity changed"}
    try:
        broker_key = load_verify_key(manifest["broker_public_key"])
    except (OSError, ValueError, TypeError):
        return {"status": "blocked", "reason": "operator broker verification key unavailable"}
    initial_boundary = _installed_boundary_snapshot(manifest)
    if initial_boundary["status"] != "ok":
        return {"status": "blocked", "reason": initial_boundary["reason"]}
    receipt = _protected_receipt_at(
        BROKER_SOCKET,
        task_id=manifest["task_id"],
        context_id=manifest["context_id"],
        generation=manifest["generation"],
        broker_verify_key=broker_key,
        ledger_dir=BROKER_LEDGER,
        expected_broker_executable=manifest["broker_executable"],
        expected_endpoint_identity=manifest["socket_identity"],
        expected_evaluator_uid=manifest["evaluator_uid"],
    )
    refreshed_installation = _load_operator_installation()
    if (refreshed_installation.get("status") != "ok"
            or refreshed_installation.get("installation") != manifest):
        return {"status": "blocked",
                "reason": "operator installation changed during protected broker IPC"}
    final_boundary = _installed_boundary_snapshot(manifest)
    if (final_boundary["status"] != "ok"
            or final_boundary["identity"] != initial_boundary["identity"]):
        return {"status": "blocked",
                "reason": "operator installation identity changed during protected broker IPC: "
                + final_boundary.get("reason", "protected inode, UID, cgroup or replay ledger differs")}
    if receipt.get("status") != "verified_uninstalled":
        return {"status": "blocked", "reason":
                "protected installed broker receipt rejected: " + receipt.get("reason", "unverified")}
    return {"status": "blocked",
            "reason": "operator-installed positive crash containment not yet attested"}

def _verifier_principal_check() -> dict[str, Any]:
    if os.getuid() != VERIFIER_UID or os.geteuid() != VERIFIER_UID:
        return {
            "status": "blocked",
            "reason": f"approve requires real and effective verifier UID {VERIFIER_UID}",
        }

    home = VERIFIER_HOME
    try:
        home_stat = os.lstat(home)
    except OSError:
        return {"status": "blocked", "reason": "verifier trust root not found"}
    if (
        not stat.S_ISDIR(home_stat.st_mode)
        or home_stat.st_uid not in (0, VERIFIER_UID)
        or home_stat.st_mode & 0o022
    ):
        return {"status": "blocked", "reason": "verifier trust root is not a protected directory"}

    grants_file = home / "grants.json"
    try:
        grants_stat = os.lstat(grants_file)
    except OSError:
        return {"status": "blocked", "reason": "verifier grants file not found"}
    if not stat.S_ISREG(grants_stat.st_mode) or grants_stat.st_uid != VERIFIER_UID:
        return {"status": "blocked", "reason": "verifier grants file not a verifier-owned regular file"}
    if grants_stat.st_mode & 0o077:
        return {"status": "blocked", "reason": "verifier grants file is group/world accessible"}

    keyring_file = home / "keyring.json"
    try:
        keyring_stat = os.lstat(keyring_file)
    except OSError:
        return {"status": "blocked", "reason": "verifier keyring file not found"}
    if (
        not stat.S_ISREG(keyring_stat.st_mode)
        or keyring_stat.st_uid not in (0, VERIFIER_UID)
        or keyring_stat.st_mode & 0o022
    ):
        return {"status": "blocked", "reason": "verifier keyring is not a protected regular file"}
    for label, path, owners in (
        ("verifier trust root", home, (0, VERIFIER_UID)),
        ("verifier grants", grants_file, (0, VERIFIER_UID)),
        ("verifier keyring", keyring_file, (0, VERIFIER_UID)),
    ):
        violation = _protected_path(path, label=label, owners=owners)
        if violation:
            return {"status": "blocked", "reason": violation}
    return _installed_verifier_admission_check()


def _run(repo: Path, command: list[str]) -> tuple[int, str, str]:
    env = {
        "PATH": os.defpath,
        "HOME": str(VERIFIER_HOME),
        "LANG": "C",
        "LC_ALL": "C",
    }
    bootstrap = (
        "import runpy, sys; "
        "sys.path.insert(0, sys.argv[1]); "
        "sys.argv = sys.argv[2:]; "
        "runpy.run_path(sys.argv[0], run_name='__main__')"
    )
    process = subprocess.run(
        [sys.executable, "-I", "-c", bootstrap, str(HERE),
         str(HERE / command[0]), *command[1:]],
        cwd=str(VERIFIER_HOME),
        env=env,
        capture_output=True, text=True, check=False,
    )
    return process.returncode, process.stdout, process.stderr


def cmd_start(args: argparse.Namespace) -> int:
    repo = args.repo.resolve()
    grant = require("record_launch")
    if grant["status"] != "ok":
        return _blocked(grant["reason"])
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
    principal = _verifier_principal_check()
    if principal["status"] != "ok":
        return _blocked(principal["reason"])
    repo = args.repo.resolve()
    if args.spec.resolve().is_relative_to(repo.resolve()):
        return _blocked("gate spec must come from verifier trust root, not implementer repo")
    if not args.spec.resolve().is_relative_to(VERIFIER_HOME.resolve()):
        return _blocked("gate spec must be in verifier trust root")
    boundary = boundary_check(grant="verify_evidence", repo=repo)
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


def cmd_broker_status(args: argparse.Namespace) -> int:
    result = probe_broker()
    print(json.dumps(result, sort_keys=True))
    return 1


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
    sub.add_parser("broker-status").set_defaults(func=cmd_broker_status)
    sub.add_parser("list").set_defaults(func=cmd_list)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
