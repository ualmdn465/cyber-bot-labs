#!/usr/bin/env bash
# Audita un directorio en busca de permisos peligrosos:
# SUID, SGID, ficheros world-writable y directorios world-writable sin sticky bit.
# Uso: bash audit_perms.sh DIRECTORIO
# Salida: 0 sin hallazgos, 1 con hallazgos, 2 error de uso.
set -u

if [[ $# -ne 1 ]]; then
    echo "Uso: $0 DIRECTORIO" >&2
    exit 2
fi

TARGET="$1"

if [[ ! -d "$TARGET" ]]; then
    echo "Error: '$TARGET' no es un directorio existente" >&2
    exit 2
fi

total=0

# Ejecuta una búsqueda, muestra el título y los resultados, y suma al total.
# $1 = título; el resto de argumentos son los filtros de find.
buscar() {
    local titulo="$1"
    shift

    local resultados
    resultados=$(find "$TARGET" -xdev "$@" -printf '%M %m %u %p\n' 2>/dev/null)

    echo "---- $titulo ----"
    if [[ -z "$resultados" ]]; then
        echo "(ninguno)"
    else
        echo "$resultados"
        total=$(( total + $(wc -l <<< "$resultados") ))
    fi
    echo
}

buscar "Ficheros con SUID" -type f -perm -4000
buscar "Ficheros con SGID" -type f -perm -2000
buscar "Ficheros con escritura global" -type f -perm -0002
buscar "Directorios con escritura global sin sticky bit" -type d -perm -0002 ! -perm -1000

echo "Total de hallazgos: $total"

if (( total > 0 )); then
    exit 1
fi
exit 0
