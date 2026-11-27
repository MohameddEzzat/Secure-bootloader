#!/usr/bin/env python3
"""A small, software-only secure boot demonstration."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
except ImportError:  # pragma: no cover - message shown by the command line
    print("Missing dependency. Install it with: python -m pip install -r requirements.txt", file=sys.stderr)
    raise SystemExit(2)


class BootError(Exception):
    """An image or boot policy validation error."""


def canonical_manifest(manifest: dict[str, Any]) -> bytes:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BootError(f"cannot read JSON file {path}: {exc}") from exc


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temp:
            temp_name = temp.name
            temp.write(data)
            temp.flush()
            os.fsync(temp.fileno())
        os.replace(temp_name, path)
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)


def load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise BootError(f"cannot load private key {path}: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise BootError("private key must be an Ed25519 PEM key")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(path.read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        raise BootError(f"cannot load public key {path}: {exc}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise BootError("trusted key must be an Ed25519 PEM key")
    return key


def generate_keys(private_path: Path, public_path: Path) -> None:
    if private_path.resolve() == public_path.resolve():
        raise BootError("private and public key paths must be different")
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    atomic_write(
        private_path,
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )
    atomic_write(
        public_path,
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )


def sign_image(image_path: Path, private_path: Path, manifest_path: Path, signature_path: Path,
               version: int, target: str) -> None:
    if version < 0:
        raise BootError("version must be zero or greater")
    if not target or len(target) > 128:
        raise BootError("target must contain between 1 and 128 characters")
    try:
        image = image_path.read_bytes()
    except OSError as exc:
        raise BootError(f"cannot read image {image_path}: {exc}") from exc
    manifest = {
        "algorithm": "Ed25519",
        "format": 1,
        "image_size": len(image),
        "image_sha256": hashlib.sha256(image).hexdigest(),
        "target": target,
        "version": version,
    }
    signature = load_private_key(private_path).sign(canonical_manifest(manifest))
    atomic_write(manifest_path, (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    atomic_write(signature_path, (signature.hex() + "\n").encode("ascii"))


def validate_manifest(value: Any) -> dict[str, Any]:
    expected = {"algorithm", "format", "image_size", "image_sha256", "target", "version"}
    if not isinstance(value, dict) or set(value) != expected:
        raise BootError("manifest has missing or unexpected fields")
    if value["algorithm"] != "Ed25519" or value["format"] != 1:
        raise BootError("unsupported manifest algorithm or format")
    if type(value["version"]) is not int or value["version"] < 0:
        raise BootError("manifest version must be a non-negative integer")
    if type(value["image_size"]) is not int or value["image_size"] < 0:
        raise BootError("manifest image_size must be a non-negative integer")
    digest = value["image_sha256"]
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise BootError("manifest image_sha256 must be a lowercase SHA-256 hex digest")
    if not isinstance(value["target"], str) or not value["target"] or len(value["target"]) > 128:
        raise BootError("manifest target is invalid")
    return value


def read_signature(path: Path) -> bytes:
    try:
        encoded = path.read_text(encoding="ascii").strip()
        signature = bytes.fromhex(encoded)
    except (OSError, UnicodeError, ValueError) as exc:
        raise BootError(f"cannot read signature {path}: {exc}") from exc
    if len(signature) != 64:
        raise BootError("Ed25519 signature must be 64 bytes")
    return signature


def boot(image_path: Path, manifest_path: Path, signature_path: Path, public_path: Path,
         state_path: Path, expected_target: str) -> int:
    manifest = validate_manifest(read_json(manifest_path))
    if manifest["target"] != expected_target:
        raise BootError(f"image target {manifest['target']!r} does not match this system {expected_target!r}")
    try:
        image = image_path.read_bytes()
    except OSError as exc:
        raise BootError(f"cannot read image {image_path}: {exc}") from exc
    digest = hashlib.sha256(image).hexdigest()
    if len(image) != manifest["image_size"] or digest != manifest["image_sha256"]:
        raise BootError("image size or SHA-256 digest does not match the signed manifest")
    try:
        load_public_key(public_path).verify(read_signature(signature_path), canonical_manifest(manifest))
    except InvalidSignature as exc:
        raise BootError("signature verification failed") from exc

    if state_path.exists():
        state = read_json(state_path)
        if not isinstance(state, dict) or type(state.get("highest_version")) is not int or state["highest_version"] < 0:
            raise BootError("rollback state is invalid; refusing to boot")
        highest = state["highest_version"]
    else:
        highest = -1
    if manifest["version"] < highest:
        raise BootError(f"rollback blocked: image version {manifest['version']} is below accepted version {highest}")

    # This state file is only a simulator. On a real device, anti-rollback state
    # must be protected from modification by an attacker.
    if manifest["version"] > highest:
        atomic_write(state_path, (json.dumps({"highest_version": manifest["version"]}, indent=2) + "\n").encode("utf-8"))
    print(f"Verified image version {manifest['version']} for {manifest['target']}.")
    print("Boot accepted (simulation only; the image was not executed).")
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="Software-only secure bootloader demonstration")
    commands = root.add_subparsers(dest="command", required=True)

    keys = commands.add_parser("keygen", help="generate an Ed25519 signing key pair")
    keys.add_argument("--private", type=Path, default=Path("keys/dev-private.pem"))
    keys.add_argument("--public", type=Path, default=Path("keys/trusted-public.pem"))

    signer = commands.add_parser("sign", help="create a signed image manifest")
    signer.add_argument("--image", type=Path, required=True)
    signer.add_argument("--private-key", type=Path, default=Path("keys/dev-private.pem"))
    signer.add_argument("--version", type=int, required=True)
    signer.add_argument("--target", required=True, help="system identifier, e.g. demo-x86_64")
    signer.add_argument("--manifest", type=Path, default=Path("release/manifest.json"))
    signer.add_argument("--signature", type=Path, default=Path("release/manifest.sig"))

    loader = commands.add_parser("boot", help="verify an image and simulate accepting it")
    loader.add_argument("--image", type=Path, required=True)
    loader.add_argument("--public-key", type=Path, default=Path("keys/trusted-public.pem"))
    loader.add_argument("--manifest", type=Path, default=Path("release/manifest.json"))
    loader.add_argument("--signature", type=Path, default=Path("release/manifest.sig"))
    loader.add_argument("--state", type=Path, default=Path("boot-state.json"))
    loader.add_argument("--target", required=True, help="system identifier this simulated device expects")
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "keygen":
            generate_keys(args.private, args.public)
            print(f"Created private signing key: {args.private}")
            print(f"Created trusted public key: {args.public}")
        elif args.command == "sign":
            sign_image(args.image, args.private_key, args.manifest, args.signature, args.version, args.target)
            print(f"Signed image metadata: {args.manifest}")
            print(f"Signature: {args.signature}")
        else:
            return boot(args.image, args.manifest, args.signature, args.public_key, args.state, args.target)
    except (BootError, OSError) as exc:
        print(f"BOOT REJECTED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
