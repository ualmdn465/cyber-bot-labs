#!/bin/bash

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
	echo "Aviso: ejecuta con sudo o puede que no veas los logs de SSH" >&2
fi

if command -v journalctl &>/dev/null; then
	LOG_SOURCE="journalctl"
elif [ -f /var/log/auth.log ]; then
	LOG_SOURCE="/var/log/auth.log"
elif [ -f /var/log/secure ]; then
	LOG_SOURCE="/var/log/secure"
else
	echo "Error: no se encontró journalctl, auth.log ni secure." >&2
	exit 1
fi

fetch_logs() {
	if [ "$LOG_SOURCE" = "journalctl" ]; then
		journalctl -u ssh -u sshd --no-pager
	else
		cat "$LOG_SOURCE"
	fi
}

resultados=$(fetch_logs |
	{ grep -oP 'Failed password.*from \K[0-9.]+' || true; } |
	sort | uniq -c | sort -nr |
	awk 'NR <=10 {printf "%-10s %-20s\n", $1, $2}')

echo "=================================================="
echo " Top 10 IPs con intentos fallidos de login (SSH)"
echo " Fuente de origen: $LOG_SOURCE"
echo "=================================================="

if [ -z "$resultados" ]; then
	echo "No se encontraron intentos fallidos"
else
	printf "%-10s %-20s\n" "Intentos" "Dirección IP"
	echo "--------------------------------------------------"
	echo "$resultados"
fi
