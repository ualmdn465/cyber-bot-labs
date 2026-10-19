"""Tests de manipulación de AES-GCM (aead_tamper_test.py)."""

import sys
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aead_tamper_test import (
    PLAINTEXT,
    encrypt_sample,
    flip_byte,
    nonce_reuse_demo,
)


def test_control_descifra_bien():
    key, nonce, ciphertext, aad = encrypt_sample()

    assert AESGCM(key).decrypt(nonce, ciphertext, aad) == PLAINTEXT


@pytest.mark.parametrize("campo", ["ciphertext", "tag", "nonce", "aad"])
def test_alterar_un_bit_lanza_invalidtag(campo):
    key, nonce, ciphertext, aad = encrypt_sample()

    if campo == "ciphertext":
        ciphertext = flip_byte(ciphertext, 0)
    elif campo == "tag":
        # La etiqueta ocupa los últimos 16 bytes.
        ciphertext = flip_byte(ciphertext, -1)
    elif campo == "nonce":
        nonce = flip_byte(nonce, 0)
    elif campo == "aad":
        aad = flip_byte(aad, 0)

    with pytest.raises(InvalidTag):
        AESGCM(key).decrypt(nonce, ciphertext, aad)


def test_nonce_reutilizado_revela_mensaje():
    recovered = nonce_reuse_demo()

    assert recovered == b"transferir 900 EUR a cuenta B"
