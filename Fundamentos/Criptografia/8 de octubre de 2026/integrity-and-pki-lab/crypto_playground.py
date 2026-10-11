#!/usr/bin/env python3
"""Demostraciones educativas de AES-GCM, SHA-256, HMAC y Ed25519."""

from __future__ import annotations

import hashlib
import hmac
import os
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def aes_gcm_demo() -> bool:
    """Cifra/descifra con AES-GCM y demuestra que un byte manipulado se detecta."""
    key = AESGCM.generate_key(bit_length=256)  # clave aleatoria de 256 bits
    aes = AESGCM(key)
    nonce = os.urandom(12)  # nonce de 96 bits; no reutilizar con la misma clave
    plaintext = b"Mensaje privado de ejemplo"
    aad = b"metadatos autenticados, no cifrados"

    ciphertext = aes.encrypt(nonce, plaintext, aad)
    recovered = aes.decrypt(nonce, ciphertext, aad)
    print("[AES-GCM] Descifrado correcto:", recovered.decode())

    tampered = bytearray(ciphertext)
    tampered[0] ^= 1  # cambia un bit del texto cifrado
    try:
        aes.decrypt(nonce, bytes(tampered), aad)
    except InvalidTag:
        print("[AES-GCM] OK: se detectó la manipulación (InvalidTag).")
        return True
    raise AssertionError("AES-GCM debería rechazar el texto cifrado alterado")


def _read_bytes(path: str | Path) -> bytes:
    return Path(path).read_bytes()


ROOT = Path(__file__).resolve().parent


def hash_demo(path: str | Path = ROOT / "sample_data" / "artifact.txt") -> bool:
    """Compara SHA-256 del archivo original y una copia con un bit alterado."""
    data = _read_bytes(path)
    changed = bytearray(data or b"\x00")
    changed[0] ^= 1

    original_hash = hashlib.sha256(data).hexdigest()
    changed_hash = hashlib.sha256(bytes(changed)).hexdigest()
    print(f"[SHA-256] original:  {original_hash}")
    print(f"[SHA-256] alterado:  {changed_hash}")
    detected = not hmac.compare_digest(original_hash, changed_hash)
    print("[SHA-256] Cambio detectado:", detected)
    assert detected
    return detected


def hmac_demo() -> bool:
    """Verifica HMAC-SHA-256 y rechaza un mensaje modificado."""
    secret = os.urandom(32)  # secreto compartido, solo para esta demo
    message = b"transferencia=25;destino=cuenta-demo"
    tag = hmac.new(secret, message, hashlib.sha256).digest()
    valid = hmac.compare_digest(tag, hmac.new(secret, message, hashlib.sha256).digest())
    tampered_message = message + b";"
    tampered_valid = hmac.compare_digest(
        tag, hmac.new(secret, tampered_message, hashlib.sha256).digest()
    )
    print("[HMAC] Mensaje original válido:", valid)
    print("[HMAC] Mensaje alterado válido:", tampered_valid)
    assert valid and not tampered_valid
    return not tampered_valid


def sign_demo() -> bool:
    """Firma con Ed25519 y comprueba que cambiar el mensaje invalida la firma."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    message = b"artefacto-de-demostracion"
    signature = private_key.sign(message)
    public_key.verify(signature, message)
    print("[Ed25519] Firma original válida.")

    try:
        public_key.verify(signature, message + b"!")
    except InvalidSignature:
        print("[Ed25519] OK: la firma no valida para el mensaje alterado.")
        return True
    raise AssertionError("La firma debería fallar para un mensaje alterado")


def main() -> None:
    demos = {
        "aes": aes_gcm_demo,
        "hash": hash_demo,
        "hmac": hmac_demo,
        "sign": sign_demo,
    }
    selected = sys.argv[1:] or list(demos)
    for name in selected:
        if name not in demos:
            raise SystemExit(f"Demo desconocida: {name}. Opciones: {', '.join(demos)}")
        print(f"\n--- {name.upper()} ---")
        demos[name]()


if __name__ == "__main__":
    main()
