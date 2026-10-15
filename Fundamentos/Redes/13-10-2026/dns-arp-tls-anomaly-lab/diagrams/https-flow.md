# Flujo HTTPS de `https://ejemplo.test` y certificado fraudulento

Diagrama de secuencia de una petición HTTPS: resolución DNS, handshake TCP, handshake TLS 1.3 y petición HTTP cifrada.

Las notas marcadas como **ATAQUE** describen qué ocurre si el ccTLD está comprometido y una CA real emite un certificado al atacante. La nota **DETECCIÓN** indica qué controles, fuera del flujo, pueden descubrirlo.

> Datos sintéticos: dominio reservado `.test` (RFC 2606) e IPs del rango de documentación 192.0.2.0/24 (RFC 5737).

```mermaid
sequenceDiagram
    participant N as Navegador
    participant R as Resolver DNS
    participant A as Servidor autoritativo
    participant W as Servidor web

    %% ---------- 1. DNS ----------
    N->>R: consulta A ejemplo.test
    R->>A: consulta A ejemplo.test
    A-->>R: 192.0.2.10 (TTL 300)
    Note over R,A: ATAQUE: el ccTLD está comprometido y los NS apuntan al atacante,<br/>que responde 192.0.2.66. DNSSEC no lo frena: el atacante controla<br/>la zona padre y firma con claves que validan correctamente.
    R-->>N: 192.0.2.10 (TTL 300)

    %% ---------- 2. TCP ----------
    Note over N,W: ATAQUE: el navegador conecta con 192.0.2.66 sin saberlo.
    N->>W: SYN
    W-->>N: SYN-ACK
    N->>W: ACK

    %% ---------- 3. TLS 1.3 ----------
    N->>W: ClientHello (SNI: ejemplo.test)
    W-->>N: ServerHello
    W-->>N: Certificate, CertificateVerify, Finished (cifrado)
    N->>N: valida el certificado (cadena, nombre, caducidad)
    Note right of N: ATAQUE: todo pasa. Una CA real emitió el certificado<br/>porque el atacante superó el reto DNS. El navegador comprueba<br/>que lo firmó una CA de confianza, no que lo pidiera el dueño.
    N->>W: Finished

    %% ---------- 4. HTTP ----------
    N->>W: GET / HTTP/1.1, Host: ejemplo.test (cifrado)
    W-->>N: 200 OK + HTML (cifrado)
    Note over N,W: DETECCIÓN (fuera del flujo): Certificate Transparency muestra un certificado<br/>que el dueño no pidió, y la monitorización del DNS detecta el cambio de NS.
```

## Qué control falla en cada paso

| Paso | Control | ¿Frena el ataque? | Motivo |
|---|---|---|---|
| Respuesta DNS | DNSSEC | No | El atacante controla la zona padre y firma con claves válidas |
| Emisión del certificado | CAA | No | El atacante controla el DNS y puede cambiar o borrar el registro CAA |
| Validación del certificado | Cadena de confianza | No | El certificado lo emitió una CA real; la cadena, el nombre y la fecha son correctos |
| Conexión HTTPS | HSTS | No | Obliga a usar HTTPS, pero el certificado es válido |
| Fuera del flujo | Certificate Transparency | **Detecta** | El certificado aparece en logs públicos y el dueño puede verlo |
| Fuera del flujo | Monitorización del DNS propio | **Detecta** | Alerta del cambio de NS o de la IP |
| Apps propias | Pinning | **Sí** | La app solo acepta la clave o la CA esperada |
