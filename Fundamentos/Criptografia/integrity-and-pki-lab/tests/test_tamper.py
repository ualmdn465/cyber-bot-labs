from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib
import hmac
import os
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from crypto_playground import aes_gcm_demo, hash_demo, hmac_demo, sign_demo


def test_aes_gcm_detects_tampered_ciphertext():
    key = AESGCM.generate_key(bit_length=256)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = bytearray(aes.encrypt(nonce, b"texto de prueba", None))
    ciphertext[0] ^= 1
    with pytest.raises(InvalidTag):
        aes.decrypt(nonce, bytes(ciphertext), None)


def test_hash_changes_after_one_bit_flip():
    original = b"archivo de prueba"
    altered = bytearray(original)
    altered[0] ^= 1
    assert hashlib.sha256(original).digest() != hashlib.sha256(bytes(altered)).digest()


def test_hmac_rejects_tampered_message():
    key = os.urandom(32)
    message = b"estado=aprobado"
    tag = hmac.new(key, message, hashlib.sha256).digest()
    altered = message + b"!"
    altered_tag = hmac.new(key, altered, hashlib.sha256).digest()
    assert hmac.compare_digest(tag, tag)
    assert not hmac.compare_digest(tag, altered_tag)


def test_ed25519_rejects_tampered_message():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    signature = private_key.sign(b"documento original")
    with pytest.raises(InvalidSignature):
        public_key.verify(signature, b"documento manipulado")


def test_demo_functions_run():
    assert aes_gcm_demo()
    assert hash_demo(ROOT / "sample_data" / "artifact.txt")
    assert hmac_demo()
    assert sign_demo()


def test_artifact_verification_detects_tampering(tmp_path):
    # Test de integración: necesita que make_ca.sh haya generado las claves.
    private_key_path = ROOT / "generated" / "artifact_ed25519.key"
    if not private_key_path.exists():
        pytest.skip("Ejecuta ./make_ca.sh antes del test de integración")
    artifact = ROOT / "sample_data" / "artifact.txt"
    altered = tmp_path / "artifact-altered.txt"
    altered.write_bytes(artifact.read_bytes() + b"X")
    subprocess.run([sys.executable, str(ROOT / "verify_artifact.py"), "sign", str(artifact)],
                   check=True, capture_output=True, text=True)
    result = subprocess.run([sys.executable, str(ROOT / "verify_artifact.py"), "verify", str(altered)],
                            capture_output=True, text=True)
    assert result.returncode == 1
    assert "coincide con el manifiesto: False" in result.stdout
    assert "Firma Ed25519 válida: False" in result.stdout
