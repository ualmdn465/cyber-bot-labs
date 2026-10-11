# Permisos en Linux

## Modelo UGO y rwx

Cada archivo tiene un dueño (**u**ser), un **g**rupo y el resto (**o**ther). Cada uno recibe tres bits:

| Bit | Archivo | Directorio |
|---|---|---|
| `r` | leer el contenido | listar los nombres de dentro |
| `w` | modificar el contenido | crear, borrar o renombrar entradas |
| `x` | ejecutarlo | atravesarlo (`cd`, acceder a lo de dentro) |

**Octal:** `r=4`, `w=2`, `x=1`, sumados por tripleta. `755` = `rwxr-xr-x` (binarios, directorios); `640` = `rw-r-----` (configuración sensible); `600` = solo el dueño.

## umask

Define qué permisos se **quitan** al crear archivos: `resultado = base & ~umask`, con base `666` para archivos y `777` para directorios. Con la `umask 0022` por defecto: archivos `644` y directorios `755`.

## /etc/passwd vs /etc/shadow

```
-rw-r--r-- root root   /etc/passwd   (644: lo lee todo el mundo, no contiene contraseñas)
-rw-r----- root shadow /etc/shadow   (640: contiene los hashes, solo root y el grupo shadow)
```

Si `shadow` fuera legible por *other*, cualquier usuario podría llevarse los hashes y crackearlos offline.

## Credenciales de un proceso (`man 7 credentials`)

Cada proceso tiene un **UID real** (quién lo lanzó) y un **UID efectivo** (con qué permisos actúa). Normalmente coinciden; los bits especiales los separan. `id` muestra los del usuario actual.

## Bits especiales

| Bit | Octal | Se ve como | Efecto | Ejemplo |
|---|---|---|---|---|
| SUID | `4000` | `s` en la x del dueño | El proceso corre con el UID efectivo del **dueño del archivo** | `/usr/bin/passwd` |
| SGID | `2000` | `s` en la x del grupo | Igual con el grupo; en directorios, los archivos nuevos heredan el grupo | carpetas compartidas |
| Sticky | `1000` | `t` en la x de other | En directorios, solo el dueño puede borrar sus archivos | `/tmp` (`1777`) |

Una `S` o `T` mayúscula indica el bit puesto sin el `x` correspondiente: suele ser un error de configuración.

## Por qué un SUID mal configurado es escalada de privilegios

Si un binario **SUID de root** permite ejecutar comandos, leer/escribir archivos o abrir una shell, todo lo que lance correrá con **UID efectivo 0**. Ejemplo con `find`:

```
find . -exec /bin/sh -p \;
```

El `-p` es necesario porque la shell, al ver que el UID real y el efectivo no coinciden, suelta los privilegios por defecto. Regla: ningún binario debe tener SUID de root sin una razón concreta, y nunca uno que permita salir de su función. Referencia de binarios abusables: **GTFOBins**.

## Enumeración en mi VM (Kali)

```
find / -perm -4000 -type f 2>/dev/null
```

`-perm -4000` busca archivos con **al menos** el bit SUID; `2>/dev/null` descarta los "permiso denegado".

<!-- Pega aquí 3-4 líneas de tu salida real, por ejemplo: -->
<!-- /usr/bin/passwd, /usr/bin/sudo, /usr/bin/su, /usr/bin/mount -->

Resultado: los binarios encontrados son los esperables en una instalación estándar (gestión de contraseñas, `sudo`, `su`, montaje), que tienen SUID por diseño y controlan lo que permiten hacer.

## Casos reales durante el laboratorio

- `captura.pcap` creada con `sudo tcpdump` → dueño root; se recupera con `sudo chown $USER:$USER`.
- `failed_logins.sh` sin bit `x` → `sudo` respondía *command not found*; se arregla con `chmod +x`.
- Carpeta compartida de VirtualBox → acceso solo tras añadir el usuario al grupo `vboxsf`.
