# Windows Event Anomaly Detector

## Problema
Detectar fuerza bruta, logons RDP anómalos y cambios en grupos privilegiados a partir de eventos de seguridad de Windows exportados a CSV. Todo el laboratorio usa datos sintéticos: usuarios inventados (`userN`, `test_*`, `svc_backup`) e IPs de los rangos de documentación RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`).

## Uso
```powershell
pwsh ./generate-sample.ps1 -Out data/synthetic-events.csv
pwsh ./detect.ps1 -In data/synthetic-events.csv -Out findings.csv
Invoke-Pester ./tests
```
Requisitos: PowerShell 7 (o Windows PowerShell 5.1) y Pester 5 (`Install-Module Pester -Scope CurrentUser -Force`). No hacen falta privilegios de administrador.

Códigos de salida de `detect.ps1`: `0` sin hallazgos, `1` con hallazgos, `2` error de entrada o de parámetros.

## Reglas
| Regla | Evento | Condición | Severidad |
|---|---|---|---|
| BruteForce | 4625 | ≥ `FailureThreshold` fallos de la misma cuenta en `WindowMinutes` (ventana móvil) | High |
| RDPOutsideHours | 4624 | `LogonType = 10` fuera de 08:00–18:00 | Medium |
| SensitiveGroupChange | 4728 / 4732 / 4756 | Alta en Administrators, Domain Admins, Enterprise Admins o Schema Admins | High |

El ID del evento de alta en grupo depende del ámbito del grupo: 4728 global (Domain Admins), 4732 local o de dominio local (Administrators), 4756 universal (Enterprise Admins, Schema Admins).

## Datos sintéticos
200 eventos. Además de la actividad normal (logons interactivos en horario), el generador inyecta:

- **3 patrones maliciosos** (los que debe detectar): 5 fallos de `test_bruteforce` en 2 min, RDP de `test_rdp` a las 23:14 y alta de `test_admin_change` en Administrators.
- **Ruido benigno** (no debe detectarse): `user3` falla 3 veces seguidas (error al escribir la contraseña), `svc_backup` falla cada 15 min (credencial caducada), un RDP legítimo a las 10:30 y un alta en el grupo `Users`.

## Umbral elegido y efecto en falsos positivos
Umbral elegido: **5 fallos en 5 minutos**. Resultado medido sobre el CSV sintético:

| Umbral | Cuentas detectadas | FP | FN |
|---|---|---|---|
| 3 fallos / 5 min | test_bruteforce, user3 | 1 (user3) | 0 |
| **5 fallos / 5 min** | **test_bruteforce** | **0** | **0** |
| 6 fallos / 5 min | — | 0 | 1 (test_bruteforce) |
| 3 fallos / 60 min | test_bruteforce, user3, svc_backup | 2 | 0 |
| 4 fallos / 60 min | test_bruteforce, svc_backup | 1 (svc_backup) | 0 |

- Bajar el umbral o alargar la ventana aumenta la sensibilidad: aparecen falsos positivos por errores humanos (user3) y por servicios con credenciales caducadas (svc_backup).
- Subir el umbral reduce el ruido, pero un atacante que haga menos intentos (o ataque lento, *low and slow*) pasa sin detectar: falso negativo.
- La regla agrupa por cuenta, así que **no detecta password spraying** (un intento por muchas cuentas). Haría falta una segunda regla que agrupe por IP de origen.

## Técnica MITRE ATT&CK
- [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/): regla BruteForce.
- [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/) + [T1021.001 Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/): regla RDPOutsideHours.
- [T1098.007 Account Manipulation: Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007/): regla SensitiveGroupChange.

T1136 (Create Account) correspondería a 4720 (creación de cuenta), que este laboratorio no detecta.

## Qué he aprendido
- Qué significan 4624/4625, los tipos de logon y por qué el tipo 10 identifica RDP.
- Que el evento de alta en grupo cambia según el ámbito del grupo (4728/4732/4756).
- Que el umbral de una regla es un compromiso entre falsos positivos y falsos negativos, y que hay que medirlo con datos que incluyan ruido benigno.
- Con `$ErrorActionPreference = "Stop"`, `Write-Error` corta el script y el código de salida deja de ser el que esperas.

## Posibles mejoras
- Correlación por IP (password spraying) y fallo seguido de éxito (4625 → 4624 de la misma cuenta).
- Identificar grupos por SID (`S-1-5-32-544`, `-512`, `-519`, `-518`) en vez de por nombre, que cambia con el idioma.
- Lectura directa de `.evtx` con `Get-WinEvent -FilterHashtable`.
- Horario laboral y fines de semana configurables.
- Traducir las reglas a Sigma.
