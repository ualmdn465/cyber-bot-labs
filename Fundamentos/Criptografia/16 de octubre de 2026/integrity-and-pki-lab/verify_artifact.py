#!/usr/bin/env python3
"""Firma y verifica un artefacto sintético con Ed25519 y un manifiesto SHA-256."""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parent
PRIVATE_KEY = ROOT / "generated" / "artifact_ed25519.key"
PUBLIC_KEY = ROOT / "generated" / "artifact_ed25519.pub"
MANIFEST = ROOT / "sample_data" / "manifest.json"
DEFAULT_ARTIFACT = ROOT / "sample_data" / "artifact.txt"
SIGNATURE = ROOT / "generated" / "artifact.sig"


def load_public_key():
    return serialization.load_pem_public_key(PUBLIC_KEY.read_bytes())


def sign(path: Path) -> None:
    if not PRIVATE_KEY.exists() or not PUBLIC_KEY.exists():
        raise SystemExit("Falta la clave. Ejecuta primero: ./make_ca.sh")
    data = path.read_bytes()
    private_key = serialization.load_pem_private_key(PRIVATE_KEY.read_bytes(), password=None)
    signature = private_key.sign(data)
    SIGNATURE.write_bytes(signature)
    digest = hashlib.sha256(data).hexdigest()
    MANIFEST.write_text(
        json.dumps({"algorithm": "sha256", "artifact": path.name, "sha256": digest}, indent=2)
        + "\n",
        encoding="utf-8",
    )
    print(f"Firma creada: {SIGNATURE.relative_to(ROOT)}")
    print(f"SHA-256: {digest}")


def verify(path: Path) -> bool:
    if not MANIFEST.exists() or not SIGNATURE.exists() or not PUBLIC_KEY.exists():
        print("Faltan manifiesto, firma o clave pública. Ejecuta el modo sign primero.")
        return False

    data = path.read_bytes()
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    actual_digest = hashlib.sha256(data).hexdigest()
    hash_ok = hmac.compare_digest(actual_digest, manifest["sha256"])
    print("SHA-256 coincide con el manifiesto:", hash_ok)

    try:
        load_public_key().verify(SIGNATURE.read_bytes(), data)
        signature_ok = True
    except InvalidSignature:
        signature_ok = False
    print("Firma Ed25519 válida:", signature_ok)
    return hash_ok and signature_ok


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in {"sign", "verify"}:
        print("Uso: python verify_artifact.py sign [archivo]")
        print("  o: python verify_artifact.py verify [archivo]")
        return 2
    path = Path(sys.argv[2]) if len(sys.argv) >= 3 else DEFAULT_ARTIFACT
    if not path.is_absolute():
        path = (Path.cwd() / path).resolve()
    if not path.is_file():
        print(f"No existe el archivo: {path}")
        return 2
    if sys.argv[1] == "sign":
        sign(path)
        return 0
    return 0 if verify(path) else 1


if __name__ == "__main__":
    raise SystemExit(main())
