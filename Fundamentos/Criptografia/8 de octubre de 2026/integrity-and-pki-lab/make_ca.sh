#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p pki generated
rm -f pki/root.* pki/intermediate.* pki/leaf.* generated/artifact_ed25519.*

# CA raíz autofirmada.
openssl genrsa -out pki/root.key 3072
openssl req -x509 -new -key pki/root.key -sha256 -days 3650 \
  -out pki/root.crt -subj "/C=ES/O=Local Crypto Lab/CN=Local Lab Root CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# CA intermedia, firmada por la raíz.
openssl genrsa -out pki/intermediate.key 3072
openssl req -new -key pki/intermediate.key -out pki/intermediate.csr \
  -subj "/C=ES/O=Local Crypto Lab/CN=Local Lab Intermediate CA"
cat > pki/intermediate.ext <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
openssl x509 -req -in pki/intermediate.csr -CA pki/root.crt -CAkey pki/root.key \
  -CAcreateserial -out pki/intermediate.crt -days 1825 -sha256 \
  -extfile pki/intermediate.ext

# Certificado hoja con SAN sintético.
openssl genrsa -out pki/leaf.key 2048
openssl req -new -key pki/leaf.key -out pki/leaf.csr \
  -subj "/C=ES/O=Local Crypto Lab/CN=lab.example.test"
cat > pki/leaf.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:lab.example.test
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
openssl x509 -req -in pki/leaf.csr -CA pki/intermediate.crt -CAkey pki/intermediate.key \
  -CAcreateserial -out pki/leaf.crt -days 365 -sha256 -extfile pki/leaf.ext

# Clave Ed25519 independiente para la firma del artefacto.
openssl genpkey -algorithm ED25519 -out generated/artifact_ed25519.key
openssl pkey -in generated/artifact_ed25519.key -pubout -out generated/artifact_ed25519.pub

echo
echo "PKI y clave Ed25519 creadas."
echo "Validación de cadena:"
openssl verify -CAfile pki/root.crt -untrusted pki/intermediate.crt pki/leaf.crt
echo "Validación de nombre:"
openssl verify -CAfile pki/root.crt -untrusted pki/intermediate.crt \
  -verify_hostname lab.example.test pki/leaf.crt
echo "Certificado caducado (se simula la fecha de dentro de 2 años con -attime):"
if openssl verify -attime "$(( $(date +%s) + 2*365*24*3600 ))" \
     -CAfile pki/root.crt -untrusted pki/intermediate.crt pki/leaf.crt; then
  echo "ERROR: debería haberlo rechazado" >&2; exit 1
else
  echo "Rechazado correctamente."
fi
echo
echo "Claves privadas de laboratorio en pki/ y generated/: no subir a Git."
