#!/usr/bin/env bash
# Comprueba que cada certificado de make_bad_certs.sh falla con SU mensaje concreto.
# Requiere haber ejecutado antes ./make_ca.sh y ./make_bad_certs.sh.
# Salida: 0 si los tres fallan como se espera, 1 si alguno no, 2 si faltan ficheros.
set -uo pipefail
cd "$(dirname "$0")/.."

# Se presupone que make_ca.sh y make_bad_certs.sh ya se ejecutaron.
if [[ ! -f pki/expired.crt ]]; then
    echo "ERROR: falta pki/expired.crt." >&2
    echo "Ejecuta primero ./make_ca.sh y ./make_bad_certs.sh." >&2
    exit 2
fi

if [[ ! -f pki/wrong_san.crt || ! -f pki/bad_ca_leaf.crt ||
      ! -f pki/intermediate.crt || ! -f pki/bad_intermediate.crt ||
      ! -f pki/root.crt ]]; then
    echo "ERROR: faltan certificados necesarios para las pruebas." >&2
    exit 2
fi

fallos=0

expect_error() {
    local esperado="$1"
    shift

    echo
    echo "Comando: $*"

    local salida
    if salida=$("$@" 2>&1); then
        echo "FALLO: el comando terminó correctamente, pero debía fallar."
        echo "$salida"
        ((fallos+=1))
        return
    fi

    echo "$salida"

    if grep -Fqi -- "$esperado" <<< "$salida"; then
        echo "OK: encontrado el error esperado: $esperado"
    else
        echo "FALLO: no se encontró el mensaje esperado: $esperado"
        ((fallos+=1))
    fi
}

# Sin -attime: el certificado tiene que estar caducado HOY por sí mismo.
echo "=== Test 1: certificado caducado ==="
expect_error "certificate has expired" \
    openssl verify \
    -CAfile pki/root.crt \
    -untrusted pki/intermediate.crt \
    pki/expired.crt

echo
echo "=== Test 2: SAN incorrecto ==="
expect_error "hostname mismatch" \
    openssl verify \
    -CAfile pki/root.crt \
    -untrusted pki/intermediate.crt \
    -verify_hostname lab.example.test \
    pki/wrong_san.crt

echo
echo "=== Test 3: intermedia con CA:FALSE ==="
expect_error "invalid CA certificate" \
    openssl verify \
    -CAfile pki/root.crt \
    -untrusted pki/bad_intermediate.crt \
    pki/bad_ca_leaf.crt

echo
if (( fallos > 0 )); then
    echo "RESULTADO: $fallos prueba(s) fallaron."
    exit 1
fi

echo "RESULTADO: las tres pruebas detectaron el error esperado."
exit 0
