#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


DEFAULT_HOME = Path.home() / ".orchestra-acceptance"
KEYRING_NAME = "keyring.json"
PRIVATE_KEY_NAME = "verifier_ed25519.pem"
PUBLIC_KEY_NAME = "verifier_ed25519.pub"
EVIDENCE_SUFFIX = ".evidence.json"


def default_home() -> Path:
    return Path.home() / ".orchestra-acceptance"


def keyring_path(home: Path | None = None) -> Path:
    return (home or default_home()) / KEYRING_NAME


def private_key_path(home: Path | None = None) -> Path:
    return (home or default_home()) / PRIVATE_KEY_NAME


def public_key_path(home: Path | None = None) -> Path:
    return (home or default_home()) / PUBLIC_KEY_NAME


def evidence_path(home: Path | None = None, stem: str = "evidence") -> Path:
    return (home or default_home()) / f"{stem}{EVIDENCE_SUFFIX}"


def load_keyring(home: Path | None = None) -> dict[str, Any]:
    path = keyring_path(home)
    if not path.is_file():
        return {"verifier_public_key": None, "trusted": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"verifier_public_key": None, "trusted": []}
    if not isinstance(data, dict):
        return {"verifier_public_key": None, "trusted": []}
    data.setdefault("verifier_public_key", None)
    data.setdefault("trusted", [])
    return data


def save_keyring(home: Path | None = None, data: dict[str, Any] | None = None) -> Path:
    target = keyring_path(home)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(data or load_keyring(home), sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    target.chmod(0o600)
    return target


def _signer():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey, serialization


def generate_keypair(home: Path | None = None) -> dict[str, str]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    target = default_home() if home is None else home
    target.mkdir(parents=True, exist_ok=True)
    private = Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    (target / PRIVATE_KEY_NAME).write_bytes(private_pem)
    (target / PRIVATE_KEY_NAME).chmod(0o600)
    (target / PUBLIC_KEY_NAME).write_bytes(public_pem)
    (target / PUBLIC_KEY_NAME).chmod(0o644)
    ring = load_keyring(target)
    ring["verifier_public_key"] = public_pem.decode("ascii")
    save_keyring(target, ring)
    return {
        "private_key": str(target / PRIVATE_KEY_NAME),
        "public_key": str(target / PUBLIC_KEY_NAME),
        "keyring": str(target / KEYRING_NAME),
        "verifier_public_key": public_pem.decode("ascii"),
    }


def load_signing_key(path: Path):
    from cryptography.hazmat.primitives import serialization

    data = Path(path).read_bytes()
    return serialization.load_pem_private_key(data, password=None)


def load_verify_key(pem_or_path: str | bytes) -> Any:
    from cryptography.hazmat.primitives import serialization

    if isinstance(pem_or_path, (str, Path)) and Path(pem_or_path).is_file():
        data = Path(pem_or_path).read_bytes()
    else:
        data = pem_or_path if isinstance(pem_or_path, bytes) else pem_or_path.encode("ascii")
    return serialization.load_pem_public_key(data) if b"BEGIN" in data else serialization.load_ssh_public_key(data)


def sign_payload(payload: dict[str, Any], signing_key) -> str:
    from cryptography.hazmat.primitives import serialization

    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = signing_key.sign(body)
    return signature.hex()


def verify_signature(payload: dict[str, Any], signature_hex: str, verify_key) -> bool:
    try:
        verify_key.verify(bytes.fromhex(signature_hex), json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        return True
    except Exception:
        return False


def trusted_verify_keys(home: Path | None = None) -> list[Any]:
    ring = load_keyring(home)
    keys: list[Any] = []
    for entry in ring.get("trusted", []) or []:
        if not isinstance(entry, dict):
            continue
        material = entry.get("public_key")
        if not material:
            continue
        try:
            keys.append(load_verify_key(material))
        except Exception:
            continue
    return keys


def verify_against_any_trusted(payload: dict[str, Any], signature_hex: str, home: Path | None = None) -> bool:
    ring = load_keyring(home)
    primary = ring.get("verifier_public_key")
    candidates: list[Any] = []
    if primary:
        try:
            candidates.append(load_verify_key(primary))
        except Exception:
            pass
    candidates.extend(trusted_verify_keys(home))
    for key in candidates:
        if verify_signature(payload, signature_hex, key):
            return True
    return False
