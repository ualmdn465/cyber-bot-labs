# Laboratorio: Verificador de integridad y cadena de confianza

Laboratorio local y defensivo. Usa datos sintéticos y claves regenerables; no conecta con servicios externos.

- **Primera parte (8 de octubre):** cifrado, hash, HMAC y firma; mini-PKI raíz → intermedia → hoja; firma de un artefacto.
- **Ampliación (16 de octubre):** manipulación de AES-GCM, reutilización de nonce y tres certificados que fallan la validación por motivos distintos.

## Problema

¿Cómo se comporta un cifrado **AEAD** cuando alguien manipula los datos, y cómo **falla** una cadena PKI mal construida?

- AES-GCM promete confidencialidad e integridad, pero solo si se usa bien: un nonce repetido rompe las dos garantías a la vez.
- Un certificado puede estar correctamente firmado y aun así no ser de fiar: puede estar caducado, ser para otro nombre o venir de una "CA" que no tiene permiso para serlo.

El laboratorio demuestra cada caso con código y comandos reproducibles, y documenta cómo lo vería un analista SOC.

## Objetivos

- Diferenciar cifrado, hash, HMAC y firma digital.
- Detectar alteraciones de un bit en el texto cifrado, la etiqueta, el nonce y la AAD de AES-GCM.
- Demostrar por qué no se puede reutilizar un nonce con la misma clave.
- Crear una PKI de laboratorio (CA raíz → CA intermedia → certificado hoja) y validarla con OpenSSL.
- Provocar tres fallos de validación distintos, cada uno con una única causa, y documentar su mensaje de error.

## Requisitos

- Python 3.10 o superior
- **OpenSSL 3.4 o superior** (para `-not_before` y `-not_after`, que generan el certificado caducado; probado con 3.6.2)
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
├── crypto_playground.py         # demos de AES-GCM, SHA-256, HMAC y Ed25519
├── aead_tamper_test.py          # NUEVO: manipulación de AES-GCM y nonce repetido
├── make_ca.sh                   # PKI buena: raíz, intermedia y hoja
├── make_bad_certs.sh            # NUEVO: tres certificados que fallan la validación
├── verify_artifact.py           # firma y verificación del artefacto
├── tests/
│   ├── test_tamper.py
│   ├── test_aead.py             # NUEVO: 6 tests de AES-GCM
│   └── test_chain_failures.sh   # NUEVO: comprueba el mensaje de error de cada certificado
└── sample_data/
    ├── artifact.txt
    └── manifest.json
```

Las claves, certificados y firmas generados se guardan en `pki/` y `generated/`; son artefactos temporales de laboratorio y están en `.gitignore`.

## Uso rápido

```bash
./make_ca.sh                      # PKI buena y clave Ed25519
./make_bad_certs.sh               # los tres certificados que fallan
python aead_tamper_test.py        # manipulación de AES-GCM y nonce repetido
python -m pytest -v               # tests de Python
bash tests/test_chain_failures.sh # tests de la cadena PKI
```

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

Validar la cadena hoja → intermedia → raíz, incluido el nombre:

```bash
openssl verify -CAfile pki/root.crt -untrusted pki/intermediate.crt \
  -verify_hostname lab.example.test pki/leaf.crt
```

Resultado esperado: `pki/leaf.crt: OK`. El certificado hoja contiene `DNS:lab.example.test`, un nombre sintético.

**Ojo:** sin `-verify_hostname`, `openssl verify` **no comprueba el nombre**, y un certificado con el SAN equivocado sale como `OK`.

## Paso 3. Ejecutar las demostraciones de criptografía

```bash
python crypto_playground.py            # las cuatro demos
python crypto_playground.py aes        # o una concreta: aes, hash, hmac, sign
```

1. **AES-GCM:** cifra y descifra; después cambia un bit del texto cifrado y el descifrado autenticado falla.
2. **SHA-256:** calcula el hash de un archivo y de una versión alterada.
3. **HMAC-SHA-256:** calcula y verifica un MAC usando una clave compartida.
4. **Ed25519:** firma un mensaje con la clave privada y lo verifica con la pública; una modificación invalida la firma.

## Paso 4. Firmar y verificar el artefacto

```bash
python verify_artifact.py sign sample_data/artifact.txt
python verify_artifact.py verify sample_data/artifact.txt
```

Simula una manipulación sin modificar el original:

```bash
cp sample_data/artifact.txt /tmp/artifact-altered.txt
printf 'X' >> /tmp/artifact-altered.txt
python verify_artifact.py verify /tmp/artifact-altered.txt
```

El comando rechaza el archivo alterado por hash incorrecto y firma inválida.

## Paso 5. Manipulación de AES-GCM y nonce repetido

```bash
python aead_tamper_test.py
```

```
=== Pruebas de integridad AES-GCM ===
Control (sin alterar): descifrado correcto
Ciphertext alterado: InvalidTag = SÍ
Etiqueta alterada: InvalidTag = SÍ
Nonce alterado: InvalidTag = SÍ
AAD alterado: InvalidTag = SÍ

=== Demostración educativa: reutilización de nonce ===
XOR(ciphertext1, ciphertext2) == XOR(plaintext1, plaintext2): True
Segundo mensaje recuperado sin la clave: transferir 900 EUR a cuenta B
```

**Qué demuestra:**

- **Alterar un solo bit** del texto cifrado, de la etiqueta (los últimos 16 bytes), del nonce o de la AAD hace que `decrypt()` lance `InvalidTag`. GCM comprueba la etiqueta **antes** de devolver nada, así que nunca entrega datos alterados.
- **Los cuatro casos dan el mismo error, a propósito.** Si la librería dijera qué parte se ha alterado, daría al atacante información para ajustar su manipulación (un *oráculo*).
- **El caso de control** (descifrar sin alterar nada) va primero: si fallara, por ejemplo por usar una clave equivocada, todas las pruebas darían `InvalidTag` sin demostrar nada.
- **Con un nonce repetido**, el XOR de los dos textos cifrados es igual al XOR de los dos mensajes en claro. Conociendo el primer mensaje se recupera el segundo **sin la clave**. Además, con dos mensajes bajo el mismo nonce, un atacante puede llegar a falsificar etiquetas: se pierden la confidencialidad y la integridad a la vez.

**Por qué es realista conocer el primer mensaje:** casi todos los mensajes tienen partes predecibles, como cabeceras HTTP, claves de un JSON o formatos fijos (`transferir … EUR a cuenta …`). Cada byte conocido de un mensaje revela el byte en la misma posición del otro.

## Paso 6. Certificados que fallan la validación

```bash
./make_bad_certs.sh
bash tests/test_chain_failures.sh
```

`make_bad_certs.sh` reutiliza la raíz y la intermedia de `make_ca.sh` y genera tres certificados. Cada uno cambia **una sola cosa** respecto a una hoja válida, para que el fallo tenga una única causa:

| Certificado | Qué cambia | Comando de verificación | Mensaje de OpenSSL 3.6 |
|---|---|---|---|
| `pki/expired.crt` | Fechas en el pasado: `-not_before 20250101000000Z -not_after 20250201000000Z` | `openssl verify -CAfile pki/root.crt -untrusted pki/intermediate.crt pki/expired.crt` | `error 10 at 0 depth lookup: certificate has expired` |
| `pki/wrong_san.crt` | `subjectAltName=DNS:otro.example.test` | `openssl verify -CAfile pki/root.crt -untrusted pki/intermediate.crt -verify_hostname lab.example.test pki/wrong_san.crt` | `error 62 at 0 depth lookup: hostname mismatch` |
| `pki/bad_ca_leaf.crt` | Firmado por `bad_intermediate.crt`, una intermedia con `CA:FALSE` (mantiene `keyCertSign`) | `openssl verify -CAfile pki/root.crt -untrusted pki/bad_intermediate.crt pki/bad_ca_leaf.crt` | `error 79 at 1 depth lookup: invalid CA certificate` |

Y un cuarto caso que ya documentaba la primera parte del laboratorio, sin generar nada nuevo:

| Caso | Comando | Mensaje |
|---|---|---|
| Falta la intermedia | `openssl verify -CAfile pki/root.crt pki/leaf.crt` | `error 20 at 0 depth lookup: unable to get local issuer certificate` |

**Cómo leer los errores:** `at N depth` indica en qué certificado falla la cadena (0 es la hoja, 1 la intermedia, 2 la raíz). Los **números** de error pueden cambiar entre versiones de OpenSSL; el **texto** es lo que identifica el fallo.

**Tres detalles que salieron al construirlos:**

- **El caducado tiene que nacer caducado.** Un certificado de un día verificado con `-attime` en el futuro *parece* caducado, pero hoy es válido. Por eso `test_chain_failures.sh` verifica **sin** `-attime`: si alguien volviera a generar un certificado válido, el test fallaría.
- **La intermedia mala conserva `keyCertSign`.** Si también se le quita, OpenSSL da dos errores a la vez (`invalid CA certificate` y `key usage does not include certificate signing`) y no se sabe cuál es la causa.
- **OpenSSL firma la intermedia mala sin quejarse.** Una CA puede emitir lo que quiera; el error aparece al **verificar**. Por eso la validación de `basicConstraints` en el cliente es crítica: sin ella, cualquier certificado de hoja podría firmar certificados para otros dominios.

## Fallos, causas y detección

| Fallo | Causa probable | Comando que lo demuestra | Cómo lo detectaría un SOC |
|---|---|---|---|
| `InvalidTag` al descifrar AES-GCM | Datos alterados en tránsito o en reposo, clave equivocada o un fallo de programación | `python aead_tamper_test.py` | Picos de errores de descifrado o autenticación en los logs de la aplicación, correlacionados por origen. Un error aislado puede ser un fallo; muchos desde el mismo origen sugieren manipulación |
| Nonce repetido en AES-GCM | Generador de nonces defectuoso, contador que se reinicia, o varias instancias que comparten clave sin coordinarse | `nonce_reuse_demo()` en `aead_tamper_test.py` | Casi invisible en el tráfico. Se detecta registrando los nonces usados por clave y alertando ante duplicados, o en revisiones de código. La prevención (nonces aleatorios de 96 bits, rotación de claves) es más eficaz que la detección |
| Certificado caducado (`error 10`) | Renovación olvidada o un servicio antiguo que nadie mantiene | `openssl verify … pki/expired.crt` | Errores de validación TLS en proxies o en los logs TLS de un IDS (como Zeek, que registra el estado de validación). Mejor aún: un inventario de certificados con alertas días antes de la caducidad |
| SAN que no coincide (`error 62`) | Certificado desplegado en el servidor equivocado, o un intermediario (MITM) que presenta un certificado válido de otro dominio | `openssl verify -verify_hostname … pki/wrong_san.crt` | Errores `hostname mismatch` en proxies y clientes. Si aparecen de golpe para un dominio que antes funcionaba, investigar posible interceptación |
| Intermedia con `CA:FALSE` (`error 79`) | Cadena mal construida, o un intento de usar un certificado de hoja como CA para emitir certificados falsos | `openssl verify -untrusted pki/bad_intermediate.crt pki/bad_ca_leaf.crt` | Errores `invalid CA certificate` en la validación. En producción no debería ocurrir nunca: cualquier caso real es de alta prioridad |
| Falta la intermedia (`error 20`) | Servidor que no envía la cadena completa | `openssl verify -CAfile pki/root.crt pki/leaf.crt` | Errores `unable to get local issuer certificate` en unos clientes y no en otros (algunos navegadores descargan la intermedia por su cuenta). La inconsistencia entre clientes es la pista |
| Raíz no autorizada en el almacén de confianza (T1553.004) | Un atacante instala su propia CA para que su interceptación no genere avisos | No se reproduce en este laboratorio | Monitorizar los cambios en el almacén de certificados de confianza del sistema y comparar con una línea base de raíces autorizadas |

## Paso 7. Ejecutar los tests

```bash
python -m pytest -v                 # test_tamper.py y test_aead.py
bash tests/test_chain_failures.sh   # requiere make_ca.sh y make_bad_certs.sh
```

`test_aead.py` contiene 6 tests:

| Test | Comprueba |
|---|---|
| `test_control_descifra_bien` | Sin alterar nada, se recupera el mensaje original |
| `test_alterar_un_bit_lanza_invalidtag[ciphertext/tag/nonce/aad]` | Un test parametrizado por cada elemento alterado: los cuatro lanzan `InvalidTag` |
| `test_nonce_reutilizado_revela_mensaje` | Con un nonce repetido se recupera el segundo mensaje exacto |

`test_chain_failures.sh` comprueba que cada certificado falla **con su mensaje concreto**, no solo que falle. Si fallara por otro motivo (por ejemplo, un fichero que falta), el test no pasaría. Sale con 0 si todo es correcto, 1 si algún caso no cuadra y 2 si faltan certificados.

En este laboratorio, que un test "pase" significa que la manipulación o el fallo se detectaron como se esperaba.

## Comparación de mecanismos

| Mecanismo | ¿Qué aporta? | ¿Usa secreto? | ¿Se puede recuperar el original? | Uso típico |
|---|---|---:|---:|---|
| Cifrado AES-GCM | Confidencialidad e integridad autenticada | Sí, clave compartida | Sí, con clave y nonce correctos | Proteger datos |
| Hash SHA-256 | Huella para comparar integridad | No | No | Detectar cambios si el hash de referencia es confiable |
| HMAC-SHA-256 | Integridad y autenticidad entre quienes comparten clave | Sí | No | Autenticar mensajes/archivos entre sistemas |
| Firma Ed25519 | Integridad, autenticidad y no repudio, verificable con clave pública | Privada para firmar; pública para verificar | No | Firmar software, documentos o artefactos |

Un hash por sí solo no autentica: un atacante que pueda reemplazar el archivo también podría reemplazar el hash publicado junto a él. HMAC requiere compartir un secreto; una firma digital permite verificar con una clave pública sin revelar la clave privada.

## Contexto defensivo MITRE ATT&CK

- **T1553.004 — Subvert Trust Controls: Install Root Certificate** (táctica Defense Impairment en ATT&CK v20): un atacante añade su propia raíz al almacén de confianza para que sus certificados no generen avisos. Es el caso opuesto a este laboratorio: aquí la cadena falla porque se valida bien; con una raíz maliciosa instalada, una cadena falsa **pasaría** la validación. Mitigaciones de ATT&CK: M1028 Operating System Configuration y M1054 Software Configuration.
- **T1195 — Supply Chain Compromise:** contexto para proteger artefactos y procesos de distribución (paso 4).

Estas técnicas se incluyen como contexto defensivo, no como instrucciones de explotación.

## Qué he aprendido

**Primera parte (8 de octubre):**

- El cifrado protege la confidencialidad; AES-GCM además detecta modificaciones mediante su etiqueta de autenticación.
- SHA-256 produce una huella, pero no cifra ni demuestra por sí solo quién creó un archivo.
- HMAC autentica datos mediante un secreto compartido.
- Ed25519 permite firmar con una clave privada y verificar con la pública.
- La confianza X.509 no se basa solo en que un certificado esté firmado: también deben validarse la cadena, las fechas, el nombre SAN, los usos permitidos y, cuando corresponda, la revocación.

**Ampliación (16 de octubre):**

- Por qué cambiar el nonce hace fallar el descifrado aunque no sea secreto, y por qué todos los fallos dan el mismo error (oráculos).
- Que un nonce repetido rompe confidencialidad e integridad a la vez, y por qué conocer parte de un mensaje es realista.
- La diferencia entre AES-CBC (sin integridad, riesgo de padding oracle) y AES-GCM.
- El caso de control: un test que siempre pasa no demuestra nada.
- Un certificado "caducado con -attime" no es un certificado caducado; el test tiene que fallar si se rompe lo que comprueba.
- Cambiar una sola variable en cada certificado malo para que cada fallo tenga una única causa.
- Que OpenSSL firma una intermedia con CA:FALSE sin quejarse: el control está en quien valida.

## Posibles mejoras

- Añadir comprobación de revocación con CRL/OCSP.
- Comparar tiempos y tamaños de RSA y Ed25519.
- Integrar la validación del certificado de firma con la política de confianza del proyecto.
- Repetir las pruebas de manipulación con **ChaCha20-Poly1305**, el otro AEAD habitual.
- **Simular una revocación**: revocar `leaf.crt` con una CRL y verificar con `openssl verify -crl_check`.
- Comprobar en `test_chain_failures.sh` que el test 3 **solo** da `invalid CA certificate`, sin el error de `keyUsage`.
- Probar **AES-GCM-SIV**, que tolera la reutilización de nonce.

## Limpieza

Los certificados, claves y firmas son regenerables. Para eliminarlos y recrearlos:

```bash
rm -rf pki generated
./make_ca.sh
./make_bad_certs.sh
```

No subas claves privadas a Git: `pki/`, `generated/` y `.venv/` ya están en `.gitignore`.

## Referencias

- [`cryptography`: AEAD (AESGCM)](https://cryptography.io/en/latest/hazmat/primitives/aead/)
- [`openssl-verify`](https://docs.openssl.org/3.6/man1/openssl-verify/) y [`openssl-x509`](https://docs.openssl.org/3.6/man1/openssl-x509/)
- [NIST SP 800-38D: especificación de GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [RFC 5280: validación de certificados X.509](https://www.rfc-editor.org/rfc/rfc5280)
- [MITRE ATT&CK T1553.004](https://attack.mitre.org/techniques/T1553/004/)
