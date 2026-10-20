#!/usr/bin/env bash
# Genera tres certificados que fallan la validación por una única causa cada uno:
#   1. expired.crt     -> caducado (fechas en el pasado; requiere OpenSSL >= 3.4)
#   2. wrong_san.crt   -> SAN que no coincide con el nombre verificado
#   3. bad_ca_leaf.crt -> firmado por una intermedia con CA:FALSE
# Requiere haber ejecutado antes ./make_ca.sh.
set -euo pipefail
cd "$(dirname "$0")"

# Este script se ejecuta después de make_ca.sh.
if [[ ! -f pki/intermediate.crt || ! -f pki/intermediate.key ]]; then
  echo "ERROR: ejecuta primero ./make_ca.sh" >&2
  exit 1
fi

if [[ ! -f pki/root.crt || ! -f pki/root.key ]]; then
  echo "ERROR: faltan los archivos de la CA raíz. Ejecuta ./make_ca.sh" >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# 1. Certificado caducado, firmado por la intermedia buena.
openssl genrsa -out pki/expired.key 2048
openssl req -new -key pki/expired.key \
  -out "$tmp/expired.csr" \
  -subj "/C=ES/O=Local Crypto Lab/CN=lab.example.test"

cat > "$tmp/expired.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:lab.example.test
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

# Fechas en el pasado: el certificado nace ya caducado y falla sin -attime.
# Solo caduca la hoja; la raíz y la intermedia siguen siendo válidas.
openssl x509 -req -in "$tmp/expired.csr" \
  -CA pki/intermediate.crt -CAkey pki/intermediate.key \
  -CAcreateserial -out pki/expired.crt \
  -not_before 20250101000000Z -not_after 20250201000000Z \
  -sha256 -extfile "$tmp/expired.ext"

# 2. Certificado con SAN incorrecto, firmado por la intermedia buena.
openssl genrsa -out pki/wrong_san.key 2048
openssl req -new -key pki/wrong_san.key \
  -out "$tmp/wrong_san.csr" \
  -subj "/C=ES/O=Local Crypto Lab/CN=lab.example.test"

cat > "$tmp/wrong_san.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:otro.example.test
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

openssl x509 -req -in "$tmp/wrong_san.csr" \
  -CA pki/intermediate.crt -CAkey pki/intermediate.key \
  -CAcreateserial -out pki/wrong_san.crt \
  -days 365 -sha256 -extfile "$tmp/wrong_san.ext"

# 3. Crear una intermedia defectuosa con CA:FALSE.
openssl genrsa -out pki/bad_intermediate.key 2048
openssl req -new -key pki/bad_intermediate.key \
  -out "$tmp/bad_intermediate.csr" \
  -subj "/C=ES/O=Local Crypto Lab/CN=Bad Intermediate CA"

# Igual que la intermedia buena salvo CA:FALSE. Se mantiene keyCertSign
# para que el único motivo del fallo sea basicConstraints.
cat > "$tmp/bad_intermediate.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

openssl x509 -req -in "$tmp/bad_intermediate.csr" \
  -CA pki/root.crt -CAkey pki/root.key \
  -CAcreateserial -out pki/bad_intermediate.crt \
  -days 365 -sha256 -extfile "$tmp/bad_intermediate.ext"

# Emitir una hoja firmada por la intermedia defectuosa.
openssl genrsa -out pki/bad_ca_leaf.key 2048
openssl req -new -key pki/bad_ca_leaf.key \
  -out "$tmp/bad_ca_leaf.csr" \
  -subj "/C=ES/O=Local Crypto Lab/CN=lab.example.test"

cat > "$tmp/bad_ca_leaf.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:lab.example.test
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

openssl x509 -req -in "$tmp/bad_ca_leaf.csr" \
  -CA pki/bad_intermediate.crt -CAkey pki/bad_intermediate.key \
  -CAcreateserial -out pki/bad_ca_leaf.crt \
  -days 365 -sha256 -extfile "$tmp/bad_ca_leaf.ext"

echo
echo "=== 1. Verificar certificado caducado ==="
if openssl verify \
  -CAfile pki/root.crt \
  -untrusted pki/intermediate.crt pki/expired.crt; then
  echo "ERROR: expired.crt debería haber fallado" >&2
  exit 1
else
  echo "OK: el certificado ha sido rechazado."
fi

echo
echo "=== 2. Verificar SAN incorrecto ==="
if openssl verify \
  -CAfile pki/root.crt \
  -untrusted pki/intermediate.crt \
  -verify_hostname lab.example.test pki/wrong_san.crt; then
  echo "ERROR: wrong_san.crt debería haber fallado" >&2
  exit 1
else
  echo "OK: el nombre del certificado ha sido rechazado."
fi

echo
echo "=== 3. Verificar intermedia con CA:FALSE ==="
if openssl verify \
  -CAfile pki/root.crt \
  -untrusted pki/bad_intermediate.crt \
  pki/bad_ca_leaf.crt; then
  echo "ERROR: bad_ca_leaf.crt debería haber fallado" >&2
  exit 1
else
  echo "OK: la cadena con intermedia inválida ha sido rechazada."
fi

echo
echo "Certificados generados en pki/."
echo "No subas las claves privadas del laboratorio a Git."
