# Laboratorio: Verificador de integridad y cadena de confianza

Laboratorio local y defensivo. Usa datos sintéticos y claves regenerables; no conecta con servicios externos.

## Objetivos

- Diferenciar cifrado, hash, HMAC y firma digital.
- Detectar alteraciones de un byte en un cifrado AES-GCM, un archivo y una firma.
- Crear una PKI de laboratorio: CA raíz → CA intermedia → certificado hoja.
- Validar la cadena con OpenSSL y comprobar el nombre del certificado.

## Requisitos

- Python 3.10 o superior
- OpenSSL
- Bash (Kali Linux ya lo incluye)
- `pip`

Instala las dependencias en un entorno virtual:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Estructura

```text
integrity-and-pki-lab/
├── .gitignore
├── README.md
├── requirements.txt
├── crypto_playground.py
├── make_ca.sh
├── verify_artifact.py
├── tests/test_tamper.py
└── sample_data/
    ├── artifact.txt
    └── manifest.json
```

Las claves, certificados y firmas generados se guardan en `pki/` y `generated/`; son artefactos temporales de laboratorio.

## Paso 1. Crear la mini-PKI y las claves de firma

```bash
chmod +x make_ca.sh
./make_ca.sh
```

El script crea una CA raíz autofirmada, una CA intermedia firmada por la raíz y un certificado hoja firmado por la intermedia. También genera una clave Ed25519 para firmar el artefacto. **No uses estas claves de laboratorio en producción.**

## Paso 2. Inspeccionar los certificados

```bash
openssl x509 -in pki/leaf.crt -noout -subject -issuer -dates -ext subjectAltName
openssl x509 -in pki/intermediate.crt -noout -subject -issuer
openssl x509 -in pki/root.crt -noout -subject -issuer
```

- `subject`: identidad declarada por el certificado.
- `issuer`: entidad que lo firmó.
- `dates`: periodo de validez.
- `subjectAltName` (SAN): nombres DNS/IP para los que se expide el certificado.

Validar la cadena hoja → intermedia → raíz:

```bash
openssl verify -CAfile pki/root.crt -untrusted pki/intermediate.crt pki/leaf.crt
```

Resultado esperado: `pki/leaf.crt: OK`.

Para probar la identidad DNS con OpenSSL:

```bash
openssl verify -CAfile pki/root.crt -untrusted pki/intermediate.crt \
  -verify_hostname lab.example.test pki/leaf.crt
```

El certificado hoja contiene `DNS:lab.example.test`. Es un nombre sintético; no se necesita ni se debe publicar.

### Casos que deben fallar

Certificado caducado (`-attime` valida como si la fecha fuera dentro de 2 años; la hoja dura 365 días):

```bash
openssl verify -attime "$(( $(date +%s) + 2*365*24*3600 ))" \
  -CAfile pki/root.crt -untrusted pki/intermediate.crt pki/leaf.crt
```

Resultado esperado: `error 10 at 0 depth lookup: certificate has expired`.

Nombre incorrecto (el SAN no contiene `otro.test`):

```bash
openssl verify -CAfile pki/root.crt -untrusted pki/intermediate.crt \
  -verify_hostname otro.test pki/leaf.crt
```

Resultado esperado: `error 62 at 0 depth lookup: hostname mismatch`.

Cadena incompleta (sin la intermedia no se puede llegar a la raíz):

```bash
openssl verify -CAfile pki/root.crt pki/leaf.crt
```

Resultado esperado: `error 20 at 0 depth lookup: unable to get local issuer certificate`. Por eso un servidor TLS debe enviar las intermedias junto con su certificado.

## Paso 3. Ejecutar las demostraciones de criptografía

```bash
python crypto_playground.py
```

El programa muestra cuatro demostraciones:

1. **AES-GCM:** cifra y descifra; después cambia un bit del texto cifrado y el descifrado autenticado falla.
2. **SHA-256:** calcula el hash de un archivo y de una versión alterada.
3. **HMAC-SHA-256:** calcula y verifica un MAC usando una clave compartida.
4. **Ed25519:** firma un mensaje con la clave privada y lo verifica con la pública; una modificación invalida la firma.

También puedes ejecutar una demo concreta:

```bash
python crypto_playground.py aes
python crypto_playground.py hash
python crypto_playground.py hmac
python crypto_playground.py sign
```

## Paso 4. Firmar y verificar el artefacto

Crea la firma del archivo sintético y guarda el hash en el manifiesto:

```bash
python verify_artifact.py sign sample_data/artifact.txt
python verify_artifact.py verify sample_data/artifact.txt
```

Ahora simula manipulación sin modificar el original:

```bash
cp sample_data/artifact.txt /tmp/artifact-altered.txt
printf 'X' >> /tmp/artifact-altered.txt
python verify_artifact.py verify /tmp/artifact-altered.txt
```

El comando debe rechazar el archivo alterado por hash incorrecto y/o firma inválida. El manifiesto y la firma corresponden al archivo original.

## Paso 5. Ejecutar los tests

```bash
pytest -q
```

Los tests comprueban que el sistema detecta la alteración del cifrado AES-GCM, la diferencia de hash y la modificación de un mensaje firmado. Resultado esperado: todos los tests pasan. En este contexto, que un test “pase” significa que la manipulación fue detectada como se esperaba.

## Comparación de mecanismos

| Mecanismo | ¿Qué aporta? | ¿Usa secreto? | ¿Se puede recuperar el original? | Uso típico |
|---|---|---:|---:|---|
| Cifrado AES-GCM | Confidencialidad e integridad autenticada | Sí, clave compartida | Sí, con clave y nonce correctos | Proteger datos |
| Hash SHA-256 | Huella para comparar integridad | No | No | Detectar cambios si el hash de referencia es confiable |
| HMAC-SHA-256 | Integridad y autenticidad entre quienes comparten clave | Sí | No | Autenticar mensajes/archivos entre sistemas |
| Firma Ed25519 | Integridad, autenticidad y evidencia verificable con clave pública | Privada para firmar; pública para verificar | No | Firmar software, documentos o artefactos |

Un hash por sí solo no autentica: un atacante que pueda reemplazar el archivo también podría reemplazar el hash publicado junto a él. HMAC requiere compartir un secreto; una firma digital permite verificar con una clave pública sin revelar la clave privada.

## Qué he aprendido

- El cifrado protege la confidencialidad; AES-GCM además detecta modificaciones mediante su etiqueta de autenticación.
- SHA-256 produce una huella, pero no cifra ni demuestra por sí solo quién creó un archivo.
- HMAC autentica datos mediante un secreto compartido.
- Ed25519 permite firmar con una clave privada y verificar con la pública.
- La confianza X.509 no se basa solo en que un certificado esté firmado: también deben validarse la cadena, las fechas, el nombre SAN, los usos permitidos y, cuando corresponda, la revocación.

## Posibles mejoras

- Añadir comprobación de revocación con CRL/OCSP.
- Comparar tiempos y tamaños de RSA y Ed25519.
- Integrar la validación del certificado de firma con la política de confianza del proyecto.

## Contexto defensivo MITRE ATT&CK

- **T1553.004 — Install Root Certificate:** relevante para detectar instalación no autorizada de raíces de confianza.
- **T1195 — Supply Chain Compromise:** contexto para proteger artefactos y procesos de distribución.

Estas técnicas se incluyen como contexto defensivo, no como instrucciones de explotación.

## Limpieza

Los certificados, claves y firmas son regenerables. Para eliminarlos y recrearlos:

```bash
rm -rf pki generated
./make_ca.sh
```

No subas claves privadas a Git: `pki/`, `generated/` y `.venv/` ya están en `.gitignore`.
