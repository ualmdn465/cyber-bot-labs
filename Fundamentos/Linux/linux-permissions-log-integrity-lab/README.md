# Linux permissions & log integrity lab

Auditoría de permisos peligrosos en Linux (SUID, SGID y ficheros o directorios escribibles por cualquiera) y detección de manipulación en logs de autenticación (líneas borradas, huecos temporales y marcas de tiempo que retroceden).

> Todos los datos son sintéticos: el directorio de prueba contiene ficheros vacíos, los usuarios son ficticios (`alice`, `bob`, `carol`, `admin`) y las IPs pertenecen al rango de documentación `192.0.2.0/24` (RFC 5737).

## Problema

¿Cómo se detectan los **permisos peligrosos** y la **manipulación de logs** en un host Linux?

- Un binario con **SUID root** se ejecuta como root lo lance quien lo lance. Si permite ejecutar comandos o leer ficheros arbitrarios, cualquier usuario puede escalar privilegios. Lo mismo con un fichero que todos pueden modificar y que un servicio lee o ejecuta.
- Un atacante con root puede **borrar sus huellas de `/var/log`**. En la campaña Cutting Edge contra Ivanti Connect Secure, los atacantes borraron logs para eliminar su rastro, según recoge MITRE ATT&CK. Por eso un log local solo es evidencia fiable si se ha enviado fuera del equipo.

Este lab construye dos herramientas: un auditor de permisos en Bash y un detector de huecos en logs en Python.

## Estructura

| Archivo | Contenido |
|---|---|
| [`setup_test_dir.sh`](setup_test_dir.sh) | Crea `/tmp/perm-lab/` con 9 ficheros y directorios de permisos variados |
| [`audit_perms.sh`](audit_perms.sh) | Busca SUID, SGID, ficheros world-writable y directorios world-writable sin sticky bit |
| [`generate_auth_logs.py`](generate_auth_logs.py) | Genera los dos logs sintéticos con semilla fija |
| [`log_gap_detector.py`](log_gap_detector.py) | Detecta secuencias duplicadas, huecos de secuencia, retrocesos y saltos temporales |
| [`sample_data/auth_synthetic.log`](sample_data/auth_synthetic.log) | Log íntegro: 219 líneas, con una ráfaga de fuerza bruta |
| [`sample_data/auth_tampered.log`](sample_data/auth_tampered.log) | El mismo log sin el login del atacante y las 10 líneas siguientes (`seq=116..126`) |
| [`sample_data/ejemplo_manual.log`](sample_data/ejemplo_manual.log) | 5 líneas escritas a mano con una línea borrada y una hora editada |

**Por qué existe `setup_test_dir.sh`:** git no guarda los bits SUID ni SGID. Si se subieran ficheros con esos permisos, al clonar el repo desaparecerían. El script recrea el directorio de prueba en cualquier VM limpia.

## Uso

```bash
# 1. Auditoría de permisos
bash setup_test_dir.sh                 # crea /tmp/perm-lab/
bash audit_perms.sh /tmp/perm-lab      # audita el directorio

# 2. Integridad de logs
python3 generate_auth_logs.py          # regenera sample_data/ (opcional: ya están en el repo)
python3 log_gap_detector.py sample_data/auth_synthetic.log
python3 log_gap_detector.py sample_data/auth_tampered.log
python3 log_gap_detector.py --max-gap 30 sample_data/ejemplo_manual.log
```

No hace falta `sudo`: SUID y SGID se pueden poner en ficheros propios, y todo trabaja en `/tmp` o en la carpeta del lab.

| Código de salida | `audit_perms.sh` | `log_gap_detector.py` |
|---|---|---|
| `0` | Sin hallazgos | Sin alertas |
| `1` | Hay hallazgos | Hay alertas |
| `2` | Falta el argumento o no es un directorio | Falta el argumento o no se puede leer el fichero |

## Resultados

### Auditoría de permisos

```
---- Ficheros con SUID ----
-rwsr-xr-x 4755 miguel /tmp/perm-lab/suid_bin

---- Ficheros con SGID ----
-rwxr-sr-x 2755 miguel /tmp/perm-lab/sgid_bin

---- Ficheros con escritura global ----
-rw-rw-rw- 666 miguel /tmp/perm-lab/world_writable.txt

---- Directorios con escritura global sin sticky bit ----
drwxrwxrwx 777 miguel /tmp/perm-lab/publico_sin_sticky

Total de hallazgos: 4
```

De los 9 elementos de prueba, el auditor marca **4** y deja fuera **dos casos que parecen peligrosos y no lo son**:

| Elemento | ¿Se marca? | Motivo |
|---|---|---|
| `compartido/` (2775) | No | SGID en un **directorio** no da privilegios: solo hace que los ficheros nuevos hereden el grupo. Es la configuración recomendada para carpetas compartidas |
| `publico_con_sticky/` (1777) | No | Es como `/tmp`: todos pueden crear ficheros, pero el sticky bit impide borrar los ajenos. Marcarlo daría un falso positivo en cada máquina |
| `publico_sin_sticky/` (777) | **Sí** | Cualquiera puede borrar o sustituir ficheros de otros usuarios |

### Detección de manipulación de logs

| Fichero | Resultado | Código |
|---|---|---|
| `auth_synthetic.log` | `OK: no se detectaron anomalías` | 0 |
| `auth_tampered.log` | `Hueco(s) de secuencia: faltan 116..126` y `Salto temporal de 638s entre seq=115 y seq=127` | 1 |
| `ejemplo_manual.log` (con `--max-gap 30`) | Hueco (falta el 3), retroceso temporal y salto de 65 s | 1 |

## Cómo funciona

### `audit_perms.sh`

Cuatro búsquedas con `find`, cada una con su filtro:

| Búsqueda | Filtro |
|---|---|
| Ficheros con SUID | `-type f -perm -4000` |
| Ficheros con SGID | `-type f -perm -2000` (solo ficheros: en directorios no es peligroso) |
| Ficheros escribibles por cualquiera | `-type f -perm -0002` |
| Directorios escribibles por cualquiera sin sticky | `-type d -perm -0002 ! -perm -1000` |

Una función `buscar` ejecuta cada búsqueda, muestra los resultados y los suma al total. Usa `-xdev` para no entrar en `/proc` ni en otros discos si se audita `/`, y descarta los errores de "Permiso denegado".

### `log_gap_detector.py`

Cada línea del log tiene un número de secuencia (`seq`) y una marca de tiempo en UTC:

```
2026-10-14T11:41:16Z seq=115 user=admin action=login result=failure source=192.0.2.50
```

| Regla | Qué detecta |
|---|---|
| Secuencia duplicada | Dos líneas con el mismo `seq`: posible línea insertada |
| Hueco de secuencia | Faltan números entre el `seq` mínimo y el máximo: líneas borradas |
| Retroceso temporal | Una línea es anterior a la que tiene encima: hora editada o línea insertada |
| Salto temporal | Más de `--max-gap` segundos entre dos `seq` consecutivos |

**El umbral por defecto es de 300 s.** Los logs sintéticos tienen una línea cada 60 ± 20 s, así que el intervalo normal más largo es de 80 s, y el borrado de 11 líneas deja un hueco de 638 s. Un umbral de 300 s queda con margen entre los dos. **El umbral depende de la cadencia de cada log**: en `ejemplo_manual.log`, con una línea cada 5 s, un hueco de 65 s ya es anómalo, y por eso se ejecuta con `--max-gap 30`.

**Sobre el número de secuencia.** El `auth.log` real no lleva número de secuencia; aquí se añade porque es lo que hace detectable un borrado. El formato syslog RFC 5424 lo permite con el campo `sequenceId`.

### Limitaciones

- **No detecta borrados al principio ni al final del fichero.** Si un atacante trunca las últimas líneas, no queda ningún hueco en medio. Solo se detecta comparando con una copia remota o con el último `seq` conocido.
- **Un atacante con root puede renumerar las líneas y recalcular las horas.** Estas reglas detectan manipulaciones torpes. Contra un atacante cuidadoso, la única defensa es que los logs ya estén fuera del equipo.
- **Falsos positivos conocidos:** la rotación de logs (`logrotate`) corta el fichero, un servicio parado de verdad no registra nada durante un rato, y un ajuste del reloj por NTP puede hacer que la hora retroceda. Por eso los logs van en UTC.

## Auditoría de servicios de la VM

Revisión de los servicios en ejecución en la VM Kali del laboratorio (`systemctl list-units --type=service --state=running`).

| Servicio | Qué hace | ¿Necesario? | Motivo |
|---|---|---|---|
| `NetworkManager`, `systemd-resolved` | Red y DNS | Sí | Sin ellos no hay conexión. `systemd-resolved` escucha solo en localhost |
| `systemd-journald`, `systemd-logind`, `systemd-udevd`, `systemd-userdbd`, `dbus`, `polkit` | Logs, sesiones, dispositivos y permisos | Sí | Base del sistema |
| `lightdm`, `accounts-daemon`, `user@1000`, `rtkit-daemon`, `getty@tty1` | Login gráfico, cuentas, sesión, audio y consola | Sí | Necesarios con entorno gráfico |
| `cron`, `virtualbox-guest-utils` | Tareas programadas e integración con VirtualBox | Sí | Los usan el sistema y la VM |
| `udisks2`, `upower` | Montaje de discos y energía | Opcional | Poco relevantes en una VM |
| `haveged` | Entropía para el generador aleatorio | Prescindible | Desde el kernel 5.6 aporta poco; es inofensivo |
| `ModemManager` | Módems 3G/4G | **No** | La VM no tiene módem |
| `pcscd` | Lectores de tarjetas inteligentes | **No** | Solo para smartcards o DNIe |
| `colord` | Perfiles de color | **No** | Irrelevante en una VM de pentesting |

**Conclusión:** no hay servidores (SSH, web, bases de datos) en ejecución, lo esperable en una VM de ataque. Candidatos a desactivar con `sudo systemctl disable --now <servicio>`: **ModemManager, pcscd, colord** y `smartmontools`, que está activado pero no tiene discos físicos que vigilar. Los 10 timers activos vienen de paquetes del sistema (apt, man-db, logrotate, plocate…).

<!-- Completar con el resultado de `sudo ss -tulpn`: qué puertos hay en escucha y en qué dirección. -->

## Técnicas MITRE ATT&CK

| Técnica | Táctica | Relación con el lab |
|---|---|---|
| [T1548.001 Abuse Elevation Control Mechanism: Setuid and Setgid](https://attack.mitre.org/techniques/T1548/001/) | Privilege Escalation | Abusar de un binario con SUID o SGID para ejecutar código con los privilegios de su propietario. Es lo que busca `audit_perms.sh`. Mitigación de ATT&CK: M1028 Operating System Configuration |
| [T1070 Indicator Removal](https://attack.mitre.org/techniques/T1070/) | Stealth | Borrar o modificar logs y otros artefactos para ocultar la actividad. Es lo que detecta `log_gap_detector.py`. Mitigaciones de ATT&CK: M1029 Remote Data Storage y M1022 Restrict File and Directory Permissions |
| [T1110.001 Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/) | Credential Access | La ráfaga de 15 intentos fallidos desde `192.0.2.50` que hay en los logs sintéticos, justo antes del login borrado |

Técnicas comprobadas en ATT&CK v20. La subtécnica más específica para el borrado de logs en Linux es T1070.002 (Clear Linux or Mac System Logs), pero no he podido abrir su ficha para confirmarla, así que se referencia la técnica padre.

## Qué he aprendido

- Que el mismo bit significa cosas distintas en ficheros y en directorios (SGID), y que "world-writable" no es peligroso si hay sticky bit.
- Que un auditor que marca /tmp y las carpetas compartidas genera falsos positivos y acaba ignorándose.
- En Bash: sin espacios alrededor del "=" en las asignaciones, y la trampa de `wc -l` con una cadena vacía.
- Que el umbral de un detector depende de la cadencia del log (60 s daba 103 falsos positivos).
- Que las marcas de tiempo nunca deberían retroceder, y que un log local no es evidencia si el atacante tiene root.
- Que git no guarda los bits SUID/SGID.


## Posibles mejoras

- Enviar los logs a un host remoto (rsyslog con TLS) y comparar la copia local con la remota.
- Hash encadenado de líneas: cada línea incluye el hash de la anterior, así que borrar o editar una rompe la cadena.
- Regla de fuerza bruta: alertar si una misma IP acumula 5 o más fallos en 60 segundos.
- Detectar truncado del final guardando el último seq conocido fuera del equipo.
- Que audit_perms.sh compare con una línea base y solo muestre lo nuevo.
- Añadir búsqueda de capabilities con getcap.


## Referencias

- [`chmod(1)`](https://man7.org/linux/man-pages/man1/chmod.1.html), [`find(1)`](https://man7.org/linux/man-pages/man1/find.1.html) y [`journalctl(1)`](https://man7.org/linux/man-pages/man1/journalctl.1.html)
- [Documentación de systemd](https://systemd.io/)
- [RFC 5424 – formato syslog](https://www.rfc-editor.org/rfc/rfc5424)
- [RFC 5737 – rangos IPv4 de documentación](https://www.rfc-editor.org/rfc/rfc5737)
- [GTFOBins](https://gtfobins.github.io/)
- [MITRE ATT&CK – Enterprise](https://attack.mitre.org/tactics/enterprise/)
