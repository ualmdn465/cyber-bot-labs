#!/usr/bin/env python3
"""Demuestra que AES-GCM detecta la alteración de 1 bit en el texto cifrado,
la etiqueta, el nonce o la AAD, y por qué no se debe reutilizar un nonce.
Todos los datos son sintéticos.

Salida: 0 si todas las alteraciones se detectan, 1 si alguna no.
"""

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PLAINTEXT = b"Mensaje de prueba para el laboratorio"
AAD = b"laboratorio=integrity-and-pki-lab"


def encrypt_sample():
    """Cifra un mensaje sintético y devuelve clave, nonce, ciphertext y AAD."""
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)  # Nonce de 96 bits recomendado para AES-GCM

    # El resultado incluye ciphertext + etiqueta de autenticación de 16 bytes.
    ciphertext = AESGCM(key).encrypt(nonce, PLAINTEXT, AAD)

    return key, nonce, ciphertext, AAD


def flip_byte(data, index):
    """Devuelve una copia de data con un bit cambiado en la posición index."""
    modified = bytearray(data)
    modified[index] ^= 0x01
    return bytes(modified)


def xor_bytes(x, y):
    """XOR byte a byte de dos secuencias de la misma longitud."""
    if len(x) != len(y):
        raise ValueError("xor_bytes necesita dos secuencias de igual longitud")
    return bytes(a ^ b for a, b in zip(x, y))


def nonce_reuse_demo():
    """Demuestra, con datos sintéticos, por qué no reutilizar nonce en AES-GCM.

    Devuelve el segundo mensaje recuperado sin usar la clave.
    """
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    message1 = b"transferir 100 EUR a cuenta A"
    message2 = b"transferir 900 EUR a cuenta B"

    # DEMOSTRACIÓN INSEGURA A PROPÓSITO: misma clave y mismo nonce dos veces.
    encrypted1 = aesgcm.encrypt(nonce, message1, None)
    encrypted2 = aesgcm.encrypt(nonce, message2, None)

    # AESGCM devuelve ciphertext seguido de una etiqueta de 16 bytes.
    ct1 = encrypted1[:-16]
    ct2 = encrypted2[:-16]

    xor_ciphertexts = xor_bytes(ct1, ct2)
    xor_plaintexts = xor_bytes(message1, message2)
    # El "atacante" solo usa los dos textos cifrados y el primer mensaje.
    recovered_message2 = xor_bytes(xor_ciphertexts, message1)

    print("\n=== Demostración educativa: reutilización de nonce ===")
    print(f"XOR(ciphertext1, ciphertext2) == XOR(plaintext1, plaintext2): "
          f"{xor_ciphertexts == xor_plaintexts}")
    print(f"Segundo mensaje recuperado sin la clave: {recovered_message2.decode('utf-8')}")
    print("Nota: solo se han usado mensajes sintéticos; no reutilices nonces en producción.")

    return recovered_message2


def main():
    key, nonce, ciphertext, aad = encrypt_sample()
    aesgcm = AESGCM(key)

    print("=== Pruebas de integridad AES-GCM ===")

    # Control: sin alterar nada, el descifrado tiene que funcionar.
    # Si falla, las pruebas siguientes no demuestran nada.
    recovered = aesgcm.decrypt(nonce, ciphertext, aad)
    assert recovered == PLAINTEXT, "El control ha fallado"
    print("Control (sin alterar): descifrado correcto")

    # Cada caso modifica exactamente uno de los elementos autenticados.
    tests = [
        ("Ciphertext alterado", nonce, flip_byte(ciphertext, 0), aad),
        ("Etiqueta alterada", nonce, flip_byte(ciphertext, -1), aad),
        ("Nonce alterado", flip_byte(nonce, 0), ciphertext, aad),
        ("AAD alterado", nonce, ciphertext, flip_byte(aad, 0)),
    ]

    failures = 0
    for name, test_nonce, test_ciphertext, test_aad in tests:
        try:
            aesgcm.decrypt(test_nonce, test_ciphertext, test_aad)
        except InvalidTag:
            print(f"{name}: InvalidTag = SÍ")
        else:
            print(f"{name}: InvalidTag = NO")
            failures += 1

    nonce_reuse_demo()

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
