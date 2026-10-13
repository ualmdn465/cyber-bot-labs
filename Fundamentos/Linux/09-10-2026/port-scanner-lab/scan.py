#!/usr/bin/env python3

import argparse
import concurrent.futures
import errno
import ipaddress
import json
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests


def parse_ports(value):
    """Acepta un puerto (8080) o un rango (8000-8100)."""
    try:
        parts = value.split("-")

        if len(parts) == 1:
            start = end = int(parts[0])
        elif len(parts) == 2:
            start, end = map(int, parts)
        else:
            raise ValueError

        if not (1 <= start <= end <= 65535):
            raise ValueError

        return list(range(start, end + 1))

    except ValueError:
        raise argparse.ArgumentTypeError(
            "Usa un puerto o rango válido, por ejemplo 8080 o 8000-8100"
        )


def validate_target(host, i_own_this_target):
    """Por defecto, solo permite la dirección IPv4 de loopback."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise ValueError("El host debe ser una dirección IP válida.")

    if not address.is_loopback and not i_own_this_target:
        raise ValueError(
            "Objetivo rechazado: usa 127.0.0.1 o "
            "--i-own-this-target si tienes autorización."
        )

    return str(address)


def scan_port(host, port, timeout):
    """Devuelve el estado TCP de un puerto."""
    result = {
        "port": port,
        "protocol": "tcp",
        "state": "error",
        "http": None,
    }

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            code = sock.connect_ex((host, port))

        if code == 0:
            result["state"] = "open"

            # Consulta HTTP únicamente en los puertos habituales del laboratorio.
            if port in (80, 8080, 8000, 8888):
                try:
                    response = requests.get(
                        f"http://{host}:{port}/",
                        timeout=timeout,
                        allow_redirects=False,
                    )
                    result["http"] = {
                        "status_code": response.status_code,
                        "headers": {
                            key: response.headers[key]
                            for key in (
                                "Server",
                                "Content-Type",
                                "X-Content-Type-Options",
                                "Content-Security-Policy",
                            )
                            if key in response.headers
                        },
                    }
                    response.close()
                except requests.RequestException as exc:
                    result["http"] = {
                        "error": type(exc).__name__
                    }

        elif code == errno.ECONNREFUSED:
            result["state"] = "closed"
        elif code in (
            errno.ETIMEDOUT,
            errno.EAGAIN,  # connect_ex devuelve esto cuando salta el timeout del socket
            getattr(errno, "EHOSTUNREACH", -1),
            getattr(errno, "ENETUNREACH", -1),
        ):
            result["state"] = "filtered"
        else:
            result["state"] = "unknown"
            result["error_code"] = code

    except socket.timeout:
        result["state"] = "filtered"
    except OSError as exc:
        if exc.errno == errno.ECONNREFUSED:
            result["state"] = "closed"
        elif exc.errno == errno.ETIMEDOUT:
            result["state"] = "filtered"
        else:
            result["state"] = "error"
            result["error"] = type(exc).__name__

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Escáner TCP connect para laboratorios autorizados."
    )
    parser.add_argument("--host", required=True, help="Dirección IPv4")
    parser.add_argument(
        "--ports", required=True, type=parse_ports,
        help="Puerto o rango, por ejemplo 8080 o 8000-8100"
    )
    parser.add_argument(
        "--timeout", type=float, default=0.5,
        help="Timeout en segundos (por defecto: 0.5)"
    )
    parser.add_argument(
        "--workers", type=int, default=10,
        help="Máximo de tareas concurrentes (por defecto: 10)"
    )
    parser.add_argument(
        "--output", default="scan_results.json",
        help="Ruta de salida JSON"
    )
    parser.add_argument(
        "--i-own-this-target", action="store_true",
        help="Confirma que tienes autorización para analizar otro objetivo"
    )

    args = parser.parse_args()

    if args.timeout <= 0 or args.timeout > 30:
        parser.error("--timeout debe ser mayor que 0 y como máximo 30.")
    if not 1 <= args.workers <= 50:
        parser.error("--workers debe estar entre 1 y 50.")

    try:
        host = validate_target(args.host, args.i_own_this_target)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    started = datetime.now(timezone.utc).isoformat()

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=args.workers
    ) as executor:
        results = list(
            executor.map(
                lambda port: scan_port(host, port, args.timeout),
                args.ports,
            )
        )

    report = {
        "target": host,
        "scan_type": "TCP connect",
        "started_at": started,
        "timeout_seconds": args.timeout,
        "results": results,
        "summary": {
            state: sum(r["state"] == state for r in results)
            for state in ("open", "closed", "filtered", "unknown", "error")
        },
    }

    output = Path(args.output)
    try:
        output.write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        print(f"Error escribiendo JSON: {exc}", file=sys.stderr)
        return 1

    for result in results:
        print(f"{result['port']:5} / tcp  {result['state']}")

    print(f"\nResultados guardados en: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
