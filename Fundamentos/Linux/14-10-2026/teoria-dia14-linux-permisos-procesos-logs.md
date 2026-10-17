# Día 14 · Teoría: permisos, procesos, logs y systemd en Linux

> Plan del día (60–90 min): **20 min de teoría** y el resto para el laboratorio `01-fundamentos/linux/linux-permissions-log-integrity-lab/`.
> Objetivo de este documento: saber auditar permisos y procesos de un host Linux y entender por qué un log local no es una prueba fiable si no sale del equipo.

## Reparto de los 20 minutos

| Minutos | Bloque | Qué tienes que salir sabiendo |
|---|---|---|
| 0–6 | 1. Permisos | Leer `rwx` y octal, calcular con `umask`, y para qué sirven y qué riesgo tienen SUID, SGID y sticky bit |
| 6–10 | 2. Procesos | Qué mirar en `ps` y en `/proc/<pid>`, y la diferencia entre `SIGTERM`, `SIGKILL` y `SIGSTOP` |
| 10–14 | 3. Logs | Dónde están los logs de autenticación, cómo consultarlos con `journalctl` y qué hace `logrotate` |
| 14–17 | 4. systemd | Qué es una unit, cómo listar servicios y timers, y por qué son un sitio típico de persistencia |
| 17–20 | 5. Integridad de logs | Por qué un atacante con root puede borrar sus huellas y qué controles lo dificultan |

Las páginas `man` y la documentación de la sección 7 son ampliación.

---

## 1. Permisos (6 min)

### 1.1 Lectura de `ls -l`

```
-rwxr-x---  1 ana  devs  4096 oct 14 10:00 script.sh
│└┬┘└┬┘└┬┘
│ │  │  └── otros (others): sin permisos
│ │  └───── grupo (devs): leer y ejecutar
│ └──────── propietario (ana): leer, escribir y ejecutar
└────────── tipo: - fichero, d directorio, l enlace simbólico
```

| Permiso | En un fichero | En un directorio |
|---|---|---|
| `r` (4) | Leer el contenido | Listar los nombres que contiene |
| `w` (2) | Modificar el contenido | Crear, borrar y renombrar entradas dentro |
| `x` (1) | Ejecutarlo | Entrar en él (`cd`) y acceder a lo que hay dentro |

Consecuencia importante: **quien tiene `w` en un directorio puede borrar ficheros de ese directorio aunque no sean suyos ni pueda escribir en ellos**. Para evitarlo existe el sticky bit (1.3).

### 1.2 Octal y `umask`

Cada grupo de tres bits se suma: `rwx` = 4+2+1 = 7, `r-x` = 5, `r--` = 4. Así, `-rwxr-x---` es **750**.

`umask` indica qué permisos se **quitan** al crear ficheros nuevos. Los ficheros parten de 666 y los directorios de 777:

| `umask` | Ficheros nuevos | Directorios nuevos | Uso típico |
|---|---|---|---|
| `022` | 644 (`rw-r--r--`) | 755 (`rwxr-xr-x`) | Valor por defecto habitual |
| `027` | 640 (`rw-r-----`) | 750 (`rwxr-x---`) | Servidores: "otros" no ven nada |
| `077` | 600 (`rw-------`) | 700 (`rwx------`) | Datos privados |

`chmod` cambia permisos (`chmod 640 f` o `chmod g+w f`) y `chown` cambia propietario y grupo (`chown ana:devs f`).

### 1.3 Bits especiales: SUID, SGID y sticky

| Bit | Octal | Cómo se ve | En un fichero | En un directorio |
|---|---|---|---|---|
| **SUID** | 4000 | `-rw`**`s`**`r-xr-x` | El programa se ejecuta con los privilegios del **propietario**, no de quien lo lanza | Sin efecto en Linux |
| **SGID** | 2000 | `-rwxr-`**`s`**`r-x` | Se ejecuta con los privilegios del **grupo** del fichero | Los ficheros nuevos heredan el grupo del directorio (útil en carpetas compartidas) |
| **Sticky** | 1000 | `drwxrwxrwx`**`t`** | Sin efecto práctico | Solo el propietario de un fichero puede borrarlo o renombrarlo, aunque otros tengan `w` en el directorio. Es lo que protege `/tmp` |

Si aparece en mayúscula (`S` o `T`), el bit está puesto pero falta el permiso `x` debajo. Suele ser un error de configuración.

**Por qué SUID root es peligroso:** cualquier usuario que ejecute ese binario lo hace como root. `passwd` necesita SUID para poder escribir en `/etc/shadow`, y está diseñado para ello. Pero si un binario con SUID root permite ejecutar comandos o leer ficheros arbitrarios (un editor, `find`, `cp`, un intérprete…), es una **escalada de privilegios** directa. GTFOBins recopila qué binarios se pueden abusar así.

Dos datos útiles:
- Linux **ignora SUID en scripts** con `#!`: solo tiene efecto en binarios compilados.
- La opción de montaje **`nosuid`** desactiva SUID y SGID en todo un sistema de ficheros. Es habitual en `/tmp` y en discos externos.

### 1.4 Comandos de auditoría

```bash
find / -xdev -type f -perm -4000 2>/dev/null                 # ficheros con SUID
find / -xdev -type f -perm -2000 2>/dev/null                 # ficheros con SGID
find / -xdev -type f -perm -0002 2>/dev/null                 # ficheros escribibles por cualquiera
find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null   # directorios escribibles por cualquiera SIN sticky
```

`-perm -4000` significa "tiene **al menos** ese bit". `-xdev` evita entrar en otros sistemas de ficheros (como `/proc`). `2>/dev/null` oculta los errores de "permiso denegado".

Las **capabilities** son otra forma de dar privilegios a un binario sin SUID completo. Se auditan con `getcap -r / 2>/dev/null`.

---

## 2. Procesos (4 min)

### 2.1 Ver procesos

```bash
ps aux                      # todos los procesos con usuario, CPU y memoria
ps -ef --forest             # árbol de procesos: quién lanzó a quién
top                         # en tiempo real (htop si está instalado)
ss -tunap                   # conexiones de red con el proceso que las abrió
```

Señales de alerta: un proceso de usuario cuyo padre es un servidor web (por ejemplo, `bash` hijo de `apache2`), nombres que imitan procesos del sistema (`[kworker]` lanzado por un usuario normal) o procesos que se ejecutan desde `/tmp` o `/dev/shm`.

### 2.2 `/proc/<pid>`: lo que el kernel sabe de cada proceso

| Entrada | Qué contiene | Para qué sirve en una investigación |
|---|---|---|
| `exe` | Enlace al binario que se está ejecutando | Si pone `(deleted)`, el binario se borró del disco pero sigue en memoria: muy sospechoso |
| `cmdline` | Línea de comandos completa, separada por `\0` | Ver argumentos: `tr '\0' ' ' < /proc/PID/cmdline` |
| `cwd` | Directorio de trabajo | Procesos trabajando en `/tmp` o en carpetas ocultas |
| `environ` | Variables de entorno | Variables como `LD_PRELOAD`, que inyectan librerías |
| `status` | Estado, `PPid`, `Uid`, memoria | Quién es el padre y con qué usuario corre |
| `fd/` | Descriptores abiertos: ficheros y sockets | Qué ficheros tiene abiertos y qué conexiones mantiene |
| `maps` | Regiones de memoria y librerías cargadas | Librerías inyectadas o cargadas desde rutas raras |

Un truco forense clave: aunque el binario se haya borrado, se puede **recuperar** mientras el proceso siga vivo con `cp /proc/PID/exe /ruta/evidencia.bin`.

### 2.3 Señales

| Señal | Número | ¿El proceso puede capturarla? | Efecto |
|---|---|---|---|
| `SIGTERM` | 15 | Sí | Petición educada de terminar: el proceso puede cerrar ficheros y limpiar. Es la que envía `kill` por defecto |
| `SIGKILL` | 9 | **No** | El kernel lo mata en el acto, sin limpieza. Último recurso |
| `SIGHUP` | 1 | Sí | Muchos demonios la usan para recargar la configuración |
| `SIGSTOP` | 19 | **No** | Congela el proceso sin matarlo |

En respuesta a incidentes, `SIGSTOP` suele ser mejor primer paso que `SIGKILL`: detiene la actividad maliciosa pero **conserva la memoria y los ficheros abiertos** para analizarlos. Matarlo destruye esa evidencia.

---

## 3. Logs (4 min)

### 3.1 Dónde están

| Fuente | Ubicación o comando | Qué contiene |
|---|---|---|
| Autenticación (Debian, Ubuntu, Kali) | `/var/log/auth.log` | Logins, `sudo`, SSH, `su` |
| Autenticación (RHEL, Fedora) | `/var/log/secure` | Lo mismo |
| Journal de systemd | `journalctl` | Todo lo anterior y más, en formato binario |
| Sesiones | `/var/log/wtmp`, `/var/log/btmp` | Logins correctos y fallidos (binarios). Se leen con `last` y `lastb` |

**Ojo en Kali y Debian recientes:** desde Debian 12, `rsyslog` ya no viene instalado por defecto, así que puede que **no exista `/var/log/auth.log`** y todo esté solo en el journal. En ese caso, usa `journalctl`.

```bash
journalctl -u ssh --since "1 hour ago"      # logs de un servicio concreto
journalctl _COMM=sudo                         # todo lo que ha registrado sudo
journalctl -p err -b                          # errores desde el último arranque
journalctl -f                                 # en tiempo real, como tail -f
```

### 3.2 Rotación con `logrotate`

Los logs crecen sin límite, así que `logrotate` los rota periódicamente: `auth.log` pasa a `auth.log.1`, el anterior a `auth.log.2.gz`, etc. La configuración está en `/etc/logrotate.conf` y `/etc/logrotate.d/`.

Esto importa para el laboratorio: **en el límite de una rotación, el fichero "salta" en el tiempo sin que nadie haya borrado nada**. Un detector de huecos tiene que tenerlo en cuenta o dará falsos positivos.

---

## 4. systemd (3 min)

systemd gestiona el arranque y los servicios mediante **units**. Las más importantes:

| Tipo | Para qué | Ejemplo |
|---|---|---|
| `.service` | Un demonio o una tarea | `ssh.service` |
| `.timer` | Ejecutar una unit periódicamente (sustituto de cron) | `logrotate.timer` |
| `.socket` | Arrancar un servicio cuando llega una conexión | `ssh.socket` |

```bash
systemctl list-units --type=service --state=running   # servicios en marcha
systemctl list-unit-files --state=enabled             # qué arranca al iniciar
systemctl list-timers                                  # tareas programadas
systemctl status ssh                                   # estado y últimas líneas de log
systemctl cat ssh                                      # contenido de la unit
```

Las units del administrador están en `/etc/systemd/system/` y las de los paquetes en `/usr/lib/systemd/system/`.

**Por qué importa en seguridad:** crear un servicio o un timer es una forma muy común de **persistencia**: el malware vuelve a arrancar en cada reinicio. Al auditar un host, busca units recientes en `/etc/systemd/system/` (ordena por fecha con `ls -lt`), sobre todo las que ejecutan algo desde `/tmp`, `/dev/shm` o un directorio de usuario. Y desactiva los servicios que no hagan falta: cada servicio en escucha es superficie de ataque.

---

## 5. Integridad de los logs (3 min)

### 5.1 El problema

Un atacante con root puede editar o borrar cualquier fichero de `/var/log`. Los logs locales registran lo que pasa, pero **quien controla el equipo controla también sus logs**.

No es teórico. En la campaña **Cutting Edge** contra Ivanti Connect Secure, MITRE ATT&CK documenta que los atacantes borraron logs para eliminar rastros y devolvieron los equipos a un estado limpio. Otro grupo, **APT5**, usó una herramienta para limpiar los logs de una VPN de Pulse Secure. Los dos aparecen como ejemplos de T1070 Indicator Removal.

### 5.2 Cómo se detecta la manipulación

- **Huecos temporales**: un servidor con actividad constante que de repente pasa minutos u horas sin registrar nada.
- **Saltos en la numeración**: si cada línea lleva un número de secuencia (RFC 5424 lo permite con el campo `sequenceId`), una línea borrada deja un salto: 41, 42, 45.
- **Incoherencias entre fuentes**: un login que aparece en `wtmp` (`last`) pero no en `auth.log`, o un evento que está en el SIEM pero no en el equipo.
- **Metadatos del fichero**: tamaño que **disminuye** entre dos revisiones (un log solo debería crecer) o una fecha de modificación incoherente.

### 5.3 Controles que lo dificultan

| Control | Qué hace | Limitación |
|---|---|---|
| **Envío a un servidor remoto** (rsyslog con TLS o un SIEM) | Cada línea sale del equipo en cuanto se escribe | Es **el control principal**. El atacante puede cortar el envío, pero no borrar lo ya enviado |
| `chattr +a` | El fichero solo admite añadir líneas, no modificarlas | Root puede quitar el atributo; sube el listón pero no impide nada |
| `auditd` | Registra quién escribe en `/var/log` (`auditctl -w /var/log -p wa`) | Si el atacante es root, también puede manipular auditd |
| **Forward Secure Sealing** del journal | Sella el journal con claves que cambian con el tiempo (`journalctl --setup-keys`) y permite comprobarlo (`journalctl --verify`) | Detecta la manipulación; no la impide |
| **Hash encadenado** | Cada línea incluye el hash de la anterior, así que borrar o editar una rompe la cadena | Hay que implementarlo, y solo detecta |
| **Mínimo privilegio** | Que poca gente tenga root | Reduce quién puede hacerlo |

Idea clave: **un log local sirve para investigar, pero solo un log que ya ha salido del equipo sirve como evidencia fiable**.

---

## 6. Preguntas de entrevista (resueltas)

### 6.1 ¿Qué riesgo supone un binario con SUID root y cómo lo auditarías?

**Riesgo:** se ejecuta como root sea quien sea quien lo lance. Si el binario tiene un fallo o una función que permite ejecutar comandos o leer y escribir ficheros arbitrarios, cualquier usuario puede escalar a root. Un ejemplo típico es una versión de `find` con SUID: `find . -exec /bin/sh -p \;` abre una shell de root.

**Auditoría:**
1. Inventariar: `find / -xdev -type f -perm -4000 2>/dev/null`.
2. Comparar con una **línea base**: lo normal en esa distribución o lo que había en el último inventario. Lo que sobra es lo primero que se mira.
3. Comprobar que pertenece a un paquete (`dpkg -S /ruta` en Debian, `rpm -qf` en RHEL) y que no se ha modificado (`debsums` o `rpm -V`).
4. Sospechar de rutas raras (`/tmp`, `/home`, `/dev/shm`) y de fechas de modificación recientes.
5. Consultar GTFOBins para saber si es abusable.
6. Reducir: quitar SUID a lo que no lo necesite (`chmod u-s`), usar `nosuid` en los puntos de montaje que lo permitan y, cuando se pueda, sustituir SUID por capabilities concretas.

### 6.2 ¿Cómo detectarías que alguien ha manipulado `/var/log` y qué controles lo harían más difícil?

**Detección:**
- Huecos temporales sin explicación en logs que normalmente tienen actividad constante.
- Saltos en números de secuencia, si los hay.
- Comparación con la copia remota (SIEM o servidor de logs): lo que está fuera y falta dentro es la prueba más clara.
- Incoherencias entre fuentes: `last` frente a `auth.log`, o el journal frente a rsyslog.
- Fichero que se hace más pequeño, o `journalctl --verify` que falla si el journal estaba sellado.
- Registros de `auditd` con escrituras en `/var/log` hechas por procesos que no son el demonio de logs.

**Controles:** el principal es **enviar los logs fuera del equipo en tiempo real**. Después, `chattr +a`, `auditd`, Forward Secure Sealing o hash encadenado, y mínimo privilegio. Hay que tener claro que los controles locales solo **detectan o dificultan**: frente a un atacante con root, lo único que conserva la evidencia es que ya esté en otro sitio.

### 6.3 ¿Qué diferencia hay entre `kill -15` y `kill -9`, y cómo investigarías un proceso sospechoso con `/proc`?

**Diferencia:** `kill -15` (`SIGTERM`) le **pide** al proceso que termine; el proceso puede capturar la señal, cerrar lo que tenga abierto y salir limpiamente, o ignorarla. `kill -9` (`SIGKILL`) no se puede capturar: el kernel lo mata en el acto, sin limpieza. Lo correcto es intentar 15 y usar 9 solo si no responde.

**Investigación con `/proc`** (antes de matarlo, porque matarlo destruye la evidencia):
1. **Congelarlo**: `kill -STOP PID`. Deja de actuar pero conserva memoria y ficheros abiertos.
2. **Qué binario es**: `ls -l /proc/PID/exe`. Si pone `(deleted)`, copiarlo con `cp /proc/PID/exe evidencia.bin`.
3. **Cómo se lanzó**: `tr '\0' ' ' < /proc/PID/cmdline`, y el padre en `/proc/PID/status` (`PPid`).
4. **Dónde trabaja y con qué entorno**: `ls -l /proc/PID/cwd` y `/proc/PID/environ` (buscar `LD_PRELOAD`).
5. **Qué tiene abierto**: `ls -l /proc/PID/fd` y `ss -tunap | grep PID` para ver conexiones.
6. **Qué librerías carga**: `/proc/PID/maps`.

Con todo documentado, ya se puede terminar el proceso.

---

## 7. Fuentes

### Páginas `man` (versión web)

- `chmod(1)`: <https://man7.org/linux/man-pages/man1/chmod.1.html>
- `find(1)`: <https://man7.org/linux/man-pages/man1/find.1.html>
- `umask(2)`: <https://man7.org/linux/man-pages/man2/umask.2.html>
- `proc(5)`, todo lo de `/proc/<pid>`: <https://man7.org/linux/man-pages/man5/proc.5.html>
- `signal(7)`: <https://man7.org/linux/man-pages/man7/signal.7.html>
- `journalctl(1)`: <https://man7.org/linux/man-pages/man1/journalctl.1.html>
- `systemd.service(5)`: <https://man7.org/linux/man-pages/man5/systemd.service.5.html>
- `chattr(1)`: <https://man7.org/linux/man-pages/man1/chattr.1.html>

### Documentación y referencias

- **systemd, documentación oficial**: <https://systemd.io/>
- **RFC 5424, formato syslog** (incluye `sequenceId`): <https://www.rfc-editor.org/rfc/rfc5424>
- **GTFOBins**, binarios abusables con SUID: <https://gtfobins.github.io/>
- **MITRE ATT&CK** (verifica las fichas al empezar el lab):
  - T1070 Indicator Removal: <https://attack.mitre.org/techniques/T1070/>
  - T1070.002 Clear Linux or Mac System Logs: <https://attack.mitre.org/techniques/T1070/002/>
  - T1548.001 Abuse Elevation Control Mechanism: Setuid and Setgid: <https://attack.mitre.org/techniques/T1548/001/>
