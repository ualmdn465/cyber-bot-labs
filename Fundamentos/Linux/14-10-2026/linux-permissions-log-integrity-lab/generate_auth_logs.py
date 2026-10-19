#!/usr/bin/env python3
"""Genera dos logs de autenticación sintéticos para log_gap_detector.py.

- sample_data/auth_synthetic.log: log íntegro.
- sample_data/auth_tampered.log: el mismo log sin el login del atacante
  y las 10 líneas siguientes, como haría alguien para ocultar su entrada.

Formato de cada línea (clave=valor):
    2026-10-14T10:00:00Z seq=1 user=alice action=login result=success source=192.0.2.10

Todos los datos son inventados: usuarios ficticios e IPs del rango de
documentación 192.0.2.0/24 (RFC 5737).
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import random

SEED = 42
START = datetime(2026, 10, 14, 10, 0, 0, tzinfo=timezone.utc)

NORMAL_LINES = 200            # líneas de actividad normal
CADENCE_SECONDS = 60          # intervalo medio entre líneas normales
JITTER_SECONDS = 20           # variación: cada intervalo está entre 40 y 80 s

BRUTE_FORCE_AFTER = 100       # la ráfaga empieza tras esta línea normal
BRUTE_FORCE_ATTEMPTS = 15     # intentos fallidos del atacante
DELETED_AFTER_LOGIN = 10      # líneas borradas tras el login del atacante

ATTACKER_IP = "192.0.2.50"
USERS = {                     # usuario -> IP habitual
    "alice": "192.0.2.10",
    "bob": "192.0.2.11",
    "carol": "192.0.2.12",
    "admin": "192.0.2.20",
}

OUTPUT_DIR = Path(__file__).resolve().parent / "sample_data"


def format_line(when: datetime, seq: int, user: str, action: str,
                result: str, source: str) -> str:
    timestamp = when.strftime("%Y-%m-%dT%H:%M:%SZ")
    return (f"{timestamp} seq={seq} user={user} action={action} "
            f"result={result} source={source}")


def next_normal_event(logged_in: set[str]) -> list[tuple[str, str, str]]:
    """Devuelve uno o dos eventos coherentes: nadie hace logout sin login."""
    user = random.choice(list(USERS))

    if user not in logged_in:
        logged_in.add(user)
        # De vez en cuando, un fallo de contraseña aislado antes de entrar.
        if random.random() < 0.1:
            return [(user, "login", "failure"), (user, "login", "success")]
        return [(user, "login", "success")]

    action = random.choice(["read", "read", "sudo" if user == "admin" else "read", "logout"])
    if action == "logout":
        logged_in.discard(user)
    return [(user, action, "success")]


def build_events() -> tuple[list[str], int]:
    """Construye todas las líneas y devuelve también el índice del login del atacante."""
    random.seed(SEED)
    lines: list[str] = []
    logged_in: set[str] = set()
    now = START
    attacker_login_index = -1

    def add(user: str, action: str, result: str, source: str) -> None:
        lines.append(format_line(now, len(lines) + 1, user, action, result, source))

    normal_count = 0
    while normal_count < NORMAL_LINES:
        for user, action, result in next_normal_event(logged_in):
            now += timedelta(seconds=CADENCE_SECONDS + random.randint(-JITTER_SECONDS, JITTER_SECONDS))
            add(user, action, result, USERS[user])
            normal_count += 1

        if normal_count >= BRUTE_FORCE_AFTER and attacker_login_index == -1:
            # Ráfaga de fuerza bruta: intentos cada 2-3 segundos desde la misma IP.
            for _ in range(BRUTE_FORCE_ATTEMPTS):
                now += timedelta(seconds=random.randint(2, 3))
                add("admin", "login", "failure", ATTACKER_IP)
            now += timedelta(seconds=random.randint(2, 3))
            add("admin", "login", "success", ATTACKER_IP)
            attacker_login_index = len(lines) - 1

            # Lo que hace el atacante justo después (también se borrará).
            for action in ["sudo", "read", "read"]:
                now += timedelta(seconds=CADENCE_SECONDS + random.randint(-JITTER_SECONDS, JITTER_SECONDS))
                add("admin", action, "success", ATTACKER_IP)

    return lines, attacker_login_index


def main() -> None:
    lines, attacker_login_index = build_events()

    # Borrado: el login del atacante y las DELETED_AFTER_LOGIN líneas siguientes.
    deleted_end = attacker_login_index + DELETED_AFTER_LOGIN + 1
    tampered = lines[:attacker_login_index] + lines[deleted_end:]

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUTPUT_DIR / "auth_synthetic.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (OUTPUT_DIR / "auth_tampered.log").write_text("\n".join(tampered) + "\n", encoding="utf-8")

    first_deleted = attacker_login_index + 1          # seq empieza en 1
    last_deleted = deleted_end
    print(f"auth_synthetic.log: {len(lines)} líneas")
    print(f"auth_tampered.log:  {len(tampered)} líneas "
          f"(borradas seq={first_deleted}..{last_deleted})")


if __name__ == "__main__":
    main()
