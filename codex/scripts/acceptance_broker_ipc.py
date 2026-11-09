from __future__ import annotations

import json
import os
import select
import secrets
import socket
import stat
import struct
import time
from pathlib import Path

BROKER_SOCKET = Path('/run/orchestra-acceptance/broker.sock')
PROTOCOL_VERSION = 1
MAX_RESPONSE = 16384
SO_PEERPIDFD = getattr(socket, 'SO_PEERPIDFD', 77)
REQUIRED_CAPABILITIES = frozenset({
    'separate-evaluator-uid', 'cgroup-v2', 'recursive-kill', 'broker-sigkill-recovery',
})


def _blocked(reason: str) -> dict[str, str]:
    return {'status': 'blocked', 'reason': reason}


def _trusted_endpoint(path: Path) -> str | None:
    if path != BROKER_SOCKET:
        return 'broker socket path is not the pinned system endpoint'
    try:
        parent = os.lstat(path.parent)
        endpoint = os.lstat(path)
    except OSError:
        return 'root-controlled broker socket is not installed'
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
        return 'broker directory is not root controlled'
    if not stat.S_ISSOCK(endpoint.st_mode) or endpoint.st_uid != 0 or endpoint.st_mode & 0o002:
        return 'broker endpoint is not a protected root-owned socket'
    return None


def _unique_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate broker response JSON field')
        result[key] = value
    return result


def _read_response(connection: socket.socket) -> dict:
    data = b''
    while b'\n' not in data:
        chunk = connection.recv(min(4096, MAX_RESPONSE + 1 - len(data)))
        if not chunk:
            raise ValueError('broker closed connection before completing response')
        data += chunk
        if len(data) > MAX_RESPONSE:
            raise ValueError('broker response exceeds size limit')
    if data.count(b'\n') != 1 or not data.endswith(b'\n'):
        raise ValueError('broker returned multiple or trailing messages')
    response = json.loads(data.decode('utf-8'), object_pairs_hook=_unique_json_keys)
    if not isinstance(response, dict):
        raise ValueError('broker response must be an object')
    return response


def _peer_exited(pidfd: int) -> bool:
    watcher = select.poll()
    watcher.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return bool(watcher.poll(0))


def _pidfd_matches_credential_pid(pidfd: int, claimed_pid: int) -> bool:
    with open(f'/proc/self/fdinfo/{pidfd}', encoding='ascii') as details:
        owners = [line.partition(':')[2].strip()
                  for line in details if line.startswith('Pid:')]
    return owners == [str(claimed_pid)]


def _probe_at(path: Path) -> dict[str, str]:
    violation = _trusted_endpoint(path)
    if violation:
        return _blocked(violation)
    nonce = secrets.token_hex(16)
    request = {'protocol': PROTOCOL_VERSION, 'operation': 'probe', 'nonce': nonce}
    peer_pidfd = None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(1.0)
            connection.connect(str(path))
            pid, uid, gid = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != 0 or pid <= 0:
                return _blocked('broker peer is not a root-owned process')
            peer_pidfd = struct.unpack('i', connection.getsockopt(
                socket.SOL_SOCKET, SO_PEERPIDFD, struct.calcsize('i')))[0]
            if peer_pidfd < 0:
                return _blocked('kernel broker peer identity pinning failed')
            if not _pidfd_matches_credential_pid(peer_pidfd, pid):
                return _blocked('broker peer PIDFD owner does not match socket credentials')
            if _peer_exited(peer_pidfd):
                return _blocked('broker peer exited before handshake')
            connection.sendall(json.dumps(request, sort_keys=True).encode('utf-8') + b'\n')
            response = _read_response(connection)
            if _peer_exited(peer_pidfd):
                return _blocked('broker peer exited during handshake')
    except (OSError, ValueError, UnicodeError, struct.error, AttributeError) as error:
        return _blocked(f'broker IPC failure: {type(error).__name__}')
    finally:
        if peer_pidfd is not None:
            os.close(peer_pidfd)
    if set(response) != {'protocol', 'operation', 'nonce', 'status', 'capabilities'}:
        return _blocked('broker response schema mismatch')
    if type(response['protocol']) is not int or response['protocol'] != PROTOCOL_VERSION or response['operation'] != 'probe' or response['nonce'] != nonce:
        return _blocked('broker response is stale or from the wrong protocol')
    capabilities = response['capabilities']
    if response['status'] != 'ready' or not isinstance(capabilities, list) or len(capabilities) != len(REQUIRED_CAPABILITIES) or not all(type(capability) is str for capability in capabilities) or set(capabilities) != REQUIRED_CAPABILITIES:
        return _blocked('broker did not advertise the required containment capabilities')
    return {'status': 'connected_unverified'}



# This challenge protocol binds one wire exchange to an explicit task/context,
# a short monotonic deadline, the current kernel UID and a held executable FD.
# It is an unprivileged NEGATIVE screen, not production attestation: a root
# broker must independently measure both verifier and evaluator OS principals,
# its installed executable and cgroup generation before any authoritative GO.
CHALLENGE_TTL_NS = 5_000_000_000


def _executable_descriptor_identity(fd: int) -> list[int]:
    details = os.fstat(fd)
    if not stat.S_ISREG(details.st_mode):
        raise ValueError('verifier executable descriptor is not a regular file')
    return [details.st_dev, details.st_ino, details.st_mode, details.st_uid]


def _attest_at(path: Path, *, task_id: str, context_id: str) -> dict[str, str]:
    """Probe a challenge-bound broker claim; NEVER return production admission."""
    for label, value in (('task', task_id), ('context', context_id)):
        if type(value) is not str or not (0 < len(value) <= 256) or any(ord(c) < 32 for c in value):
            return _blocked(f'invalid broker challenge {label} identifier')
    violation = _trusted_endpoint(path)
    if violation:
        return _blocked(violation)

    peer_pidfd = None
    executable_fd = None
    try:
        if not hasattr(os, 'O_PATH'):
            return _blocked('immutable executable descriptor pinning unavailable')
        executable_fd = os.open('/proc/self/exe', os.O_PATH | os.O_CLOEXEC)
        pinned_executable = _executable_descriptor_identity(executable_fd)
        verifier_uid, verifier_euid = os.getuid(), os.geteuid()
        issued = time.monotonic_ns()
        expires = issued + CHALLENGE_TTL_NS
        request = {
            'protocol': 2, 'operation': 'attest', 'nonce': secrets.token_hex(32),
            'task_id': task_id, 'context_id': context_id,
            'issued_monotonic_ns': issued, 'expires_monotonic_ns': expires,
            'verifier_pid': os.getpid(), 'verifier_uid': verifier_uid,
            'verifier_euid': verifier_euid, 'verifier_executable': pinned_executable,
        }
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(1.0)
            connection.connect(str(path))
            peer_pid, peer_uid, _peer_gid = struct.unpack(
                '3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if peer_uid != 0 or peer_pid <= 0:
                return _blocked('broker peer is not a root-owned process')
            peer_pidfd = struct.unpack('i', connection.getsockopt(
                socket.SOL_SOCKET, SO_PEERPIDFD, struct.calcsize('i')))[0]
            if peer_pidfd < 0 or not _pidfd_matches_credential_pid(peer_pidfd, peer_pid):
                return _blocked('broker peer PIDFD identity mismatch')
            if _peer_exited(peer_pidfd):
                return _blocked('broker peer exited before challenge')
            connection.sendall(json.dumps(request, sort_keys=True).encode('utf-8') + b'\\n')
            response = _read_response(connection)
            if _peer_exited(peer_pidfd):
                return _blocked('broker peer exited during challenge')

        elapsed = time.monotonic_ns()
        if elapsed < issued or elapsed > expires:
            return _blocked('broker challenge expired or monotonic clock changed')
        if (os.getuid(), os.geteuid()) != (verifier_uid, verifier_euid):
            return _blocked('verifier kernel UID changed during broker challenge')
        if _executable_descriptor_identity(executable_fd) != pinned_executable:
            return _blocked('verifier executable descriptor changed during challenge')
    except (OSError, ValueError, TypeError, UnicodeError, struct.error, AttributeError) as error:
        return _blocked(f'broker attestation IPC failure: {type(error).__name__}')
    finally:
        if peer_pidfd is not None:
            os.close(peer_pidfd)
        if executable_fd is not None:
            os.close(executable_fd)

    expected = set(request) | {'status', 'capabilities', 'evaluator_uid'}
    if set(response) != expected:
        return _blocked('broker attestation response schema mismatch')
    for field, value in request.items():
        claimed = response[field]
        if type(claimed) is not type(value) or claimed != value:
            return _blocked(f'broker attestation challenge binding mismatch: {field}')
    evaluator_uid = response['evaluator_uid']
    if type(evaluator_uid) is not int or evaluator_uid in (0, verifier_uid):
        return _blocked('broker evaluator UID is not a distinct unprivileged principal')
    capabilities = response['capabilities']
    if (response['status'] != 'ready' or type(capabilities) is not list
            or len(capabilities) != len(REQUIRED_CAPABILITIES)
            or not all(type(capability) is str for capability in capabilities)
            or set(capabilities) != REQUIRED_CAPABILITIES):
        return _blocked('broker attestation capabilities or status mismatch')
    # This is intentionally NOT an "attested" or "accepted" status: broker
    # signatures, kernel-observed evaluator identity, cgroup process lineage
    # and protected installed launcher still need separate operator proof.
    return {'status': 'connected_unverified'}


def attest_broker(*, task_id: str, context_id: str) -> dict[str, str]:
    return _attest_at(BROKER_SOCKET, task_id=task_id, context_id=context_id)


def probe_broker() -> dict[str, str]:
    return _probe_at(BROKER_SOCKET)
