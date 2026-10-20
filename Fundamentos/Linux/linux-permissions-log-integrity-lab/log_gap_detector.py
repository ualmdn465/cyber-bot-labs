#!/usr/bin/env python3
"""Detecta manipulación en un log sintético de autenticación.

Reglas:
- Secuencia duplicada: dos líneas con el mismo seq.
- Hueco de secuencia: faltan números entre el seq mínimo y el máximo.
- Retroceso temporal: una línea es anterior a la que tiene encima.
- Salto temporal: más de --max-gap segundos entre dos seq consecutivos.

Salida: 0 sin alertas, 1 con alertas, 2 error de uso o de lectura.
"""

import argparse
import re
import sys
from datetime import datetime
from pathlib import Path

# Por encima del intervalo normal más largo (60 ± 20 s = 80 s) y por debajo
# del hueco que deja un borrado (~638 s en auth_tampered.log).
DEFAULT_MAX_GAP = 300

LINE_RE = re.compile(
    r"^(?P<timestamp>\S+) seq=(?P<seq>\d+) user=(?P<user>\S+) "
    r"action=(?P<action>\S+) result=(?P<result>\S+) source=(?P<source>\S+)$"
)


def format_ranges(numbers: list[int]) -> str:
    """Convierte [3, 116, 117, 118] en "3, 116..118"."""
    ranges = []
    start = prev = numbers[0]

    for n in numbers[1:]:
        if n == prev + 1:
            prev = n
            continue
        ranges.append(str(start) if start == prev else f"{start}..{prev}")
        start = prev = n

    ranges.append(str(start) if start == prev else f"{start}..{prev}")
    return ", ".join(ranges)


def analyze(path: Path, max_gap: int = DEFAULT_MAX_GAP) -> list[str]:
    alerts = []
    rows = []
    seen = set()

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValueError(f"No se puede leer el fichero: {exc}") from exc

    for line_no, line in enumerate(lines, start=1):
        if not line.strip():
            continue

        match = LINE_RE.match(line.strip())

        if not match:
            alerts.append(f"Línea {line_no}: formato inválido")
            continue

        data = match.groupdict()

        try:
            timestamp = datetime.fromisoformat(
                data["timestamp"].replace("Z", "+00:00")
            )
        except ValueError:
            alerts.append(f"Línea {line_no}: timestamp inválido")
            continue

        seq = int(data["seq"])

        if seq in seen:
            alerts.append(
                f"Secuencia duplicada: seq={seq} (línea {line_no})"
            )

        seen.add(seq)
        rows.append((seq, timestamp, line_no))

    if not rows:
        return alerts

    present = {row[0] for row in rows}
    missing = [
        n for n in range(min(present), max(present) + 1)
        if n not in present
    ]

    if missing:
        alerts.append(
            f"Hueco(s) de secuencia: faltan {format_ranges(missing)}"
        )

    # Detectar retrocesos temporales según el orden del fichero
    # (rows ya está en ese orden porque se rellena línea a línea).
    for previous, current in zip(rows, rows[1:]):
        if current[1] < previous[1]:
            alerts.append(
                f"Retroceso temporal: línea {current[2]} "
                f"es anterior a línea {previous[2]}"
            )

    # Detectar saltos temporales al ordenar por secuencia.
    by_seq = sorted(rows, key=lambda row: row[0])

    for previous, current in zip(by_seq, by_seq[1:]):
        seconds = (current[1] - previous[1]).total_seconds()

        if seconds > max_gap:
            alerts.append(
                f"Salto temporal de {seconds:.0f}s "
                f"entre seq={previous[0]} y seq={current[0]}"
            )

    return alerts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logfile", type=Path)
    parser.add_argument(
        "--max-gap",
        type=int,
        default=DEFAULT_MAX_GAP,
        help="Salto temporal máximo permitido en segundos",
    )
    args = parser.parse_args()

    if args.max_gap < 0:
        print("Error: --max-gap debe ser >= 0", file=sys.stderr)
        return 2

    try:
        alerts = analyze(args.logfile, args.max_gap)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if alerts:
        print("ALERTAS:")
        for alert in alerts:
            print(f"- {alert}")
        return 1

    print("OK: no se detectaron anomalías")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
