from __future__ import annotations

import ctypes
import os
import secrets
import sys
from pathlib import Path

CGROUP_ROOT = Path('/sys/fs/cgroup')
CGROUP2_SUPER_MAGIC = 0x63677270


def _is_kernel_cgroup_v2(path: Path) -> bool:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        statfs = libc.statfs
        statfs.argtypes = (ctypes.c_char_p, ctypes.c_void_p)
        statfs.restype = ctypes.c_int
        data = ctypes.create_string_buffer(256)
        return statfs(os.fsencode(path), data) == 0 and ctypes.c_long.from_buffer(data).value == CGROUP2_SUPER_MAGIC
    except (OSError, AttributeError, ValueError):
        return False


def probe_unprivileged_delegation() -> dict[str, str | int]:
    if not sys.platform.startswith('linux'):
        return {'status': 'blocked', 'reason': 'cgroup v2 requires Linux'}
    if os.geteuid() == 0:
        return {'status': 'blocked', 'reason': 'probe must run as an unprivileged UID'}
    if not _is_kernel_cgroup_v2(CGROUP_ROOT):
        return {'status': 'blocked', 'reason': 'delegation root is not a kernel cgroup v2 filesystem'}
    if not (CGROUP_ROOT / 'cgroup.controllers').is_file():
        return {'status': 'blocked', 'reason': 'cgroup v2 controllers file is unavailable'}
    path = CGROUP_ROOT / f'orchestra-delegation-probe-{os.getpid()}-{secrets.token_hex(8)}'
    try:
        path.mkdir(mode=0o700)
    except OSError as error:
        return {
            'status': 'blocked',
            'reason': f'no writable delegated cgroup: {error.strerror}',
            'errno': error.errno or 0,
        }
    fd = None
    failure = None
    same_generation = False
    removed_generation = False
    available = False
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        original = os.fstat(fd)
        available = (path / 'cgroup.procs').is_file() and (path / 'cgroup.kill').is_file()
        current = os.stat(path, follow_symlinks=False)
        same_generation = (original.st_dev, original.st_ino) == (current.st_dev, current.st_ino)
    except OSError as error:
        failure = f'cgroup generation inspection failed: {error.strerror}'
    finally:
        try:
            path.rmdir()
        except OSError as error:
            failure = f'cgroup probe cleanup failed: {error.strerror}'
        if fd is not None:
            try:
                removed_generation = os.fstat(fd).st_nlink == 0
            except OSError:
                failure = 'cgroup generation could not be verified after cleanup'
            finally:
                os.close(fd)
    if failure:
        return {'status': 'blocked', 'reason': failure}
    if not same_generation or not removed_generation:
        return {'status': 'blocked', 'reason': 'cgroup generation changed during delegation preflight'}
    if not available:
        return {'status': 'blocked', 'reason': 'delegated cgroup lacks cgroup.procs or cgroup.kill'}
    return {
        'status': 'delegated_unverified',
        'reason': 'mkdir preflight succeeded; no process placement, fencing, or recursive-kill proof',
    }
