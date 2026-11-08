from __future__ import annotations

import json
import os
import select
import secrets
import socket
import stat
import struct
from pathlib import Path

BROKER_SOCKET = Path('/run/orchestra-acceptance/broker.sock')
PROTOCOL_VERSION = 1
MAX_RESPONSE = 16384
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
    response = json.loads(data.decode('utf-8'))
    if not isinstance(response, dict):
        raise ValueError('broker response must be an object')
    return response


def _peer_exited(pidfd: int) -> bool:
    """A pidfd pins the kernel process identity despite PID reuse or reparenting."""
    watcher = select.poll()
    watcher.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return bool(watcher.poll(0))


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
            # SO_PEERCRED can outlive the peer. Pin the *exact* kernel process,
            # not a reusable numeric PID, before trusting the reply at all.
            if not hasattr(os, 'pidfd_open'):
                return _blocked('broker process identity pinning unavailable')
            peer_pidfd = os.pidfd_open(pid, 0)
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
    if response['protocol'] != PROTOCOL_VERSION or response['operation'] != 'probe' or response['nonce'] != nonce:
        return _blocked('broker response is stale or from the wrong protocol')
    capabilities = response['capabilities']
    if response['status'] != 'ready' or not isinstance(capabilities, list) or len(capabilities) != len(REQUIRED_CAPABILITIES) or not all(type(capability) is str for capability in capabilities) or set(capabilities) != REQUIRED_CAPABILITIES:
        return _blocked('broker did not advertise the required containment capabilities')
    return {'status': 'connected_unverified'}


def probe_broker() -> dict[str, str]:
    return _probe_at(BROKER_SOCKET)
