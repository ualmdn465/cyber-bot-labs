#!/bin/bash
# Crea un directorio de prueba con permisos variados para audit_perms.sh.
# Los ficheros están vacíos: solo importan los permisos.
set -euo pipefail

TARGET="/tmp/perm-lab"

# Protección antes del rm -rf: solo se borra esta ruta exacta.
if [[ "$TARGET" != "/tmp/perm-lab" ]]; then
    echo "Error: ruta de prueba inesperada" >&2
    exit 1
fi

rm -rf -- "$TARGET"
mkdir -p "$TARGET/compartido" "$TARGET/publico_sin_sticky" "$TARGET/publico_con_sticky"
touch "$TARGET"/{normal.txt,privado.txt,script.sh,suid_bin,sgid_bin,world_writable.txt}

# Permisos explícitos: el resultado no depende del umask.
chmod 644  "$TARGET/normal.txt"
chmod 600  "$TARGET/privado.txt"
chmod 755  "$TARGET/script.sh"
chmod 4755 "$TARGET/suid_bin"
chmod 2755 "$TARGET/sgid_bin"
chmod 666  "$TARGET/world_writable.txt"
chmod 2775 "$TARGET/compartido"
chmod 777  "$TARGET/publico_sin_sticky"
chmod 1777 "$TARGET/publico_con_sticky"

stat -c '%A %a %n' "$TARGET"/*
