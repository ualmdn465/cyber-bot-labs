#!/usr/bin/env python3
"""Analizador sintético de anomalías DNS, ARP y TLS."""

import json
import math
import sys
from collections import Counter
from pathlib import Path

MIN_LABEL_LENGTH = 20
ENTROPY_THRESHOLD = 3.5


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0

    frequencies = Counter(text)
    length = len(text)
    entropy = 0.0

    for count in frequencies.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def detect_dns(events: list[dict]) -> list[dict]:
    alerts = []

    for event in events:
        if event.get("type") != "DNS":
            continue

        query = event.get("query", "")
        first_label = query.split(".")[0]
        entropy = shannon_entropy(first_label)

        if (
            len(first_label) >= MIN_LABEL_LENGTH
            and entropy >= ENTROPY_THRESHOLD
        ):
            alerts.append({
                "rule": "DNS_SUSPICIOUS_LABEL",
                "event_id": event.get("id", "unknown"),
                "detail": (
                    f"Etiqueta DNS sospechosa: {first_label!r}; "
                    f"longitud={len(first_label)}, "
                    f"entropía={entropy:.2f}"
                ),
            })

    return alerts


def detect_arp(events: list[dict]) -> list[dict]:
    alerts = []
    first_mac_by_ip = {}

    for event in events:
        if event.get("type") != "ARP":
            continue

        ip = event.get("ip")
        mac = event.get("mac")

        if not ip or not mac:
            continue

        if ip not in first_mac_by_ip:
            first_mac_by_ip[ip] = mac

        elif first_mac_by_ip[ip].lower() != mac.lower():
            alerts.append({
                "rule": "ARP_DUPLICADO",
                "event_id": event.get("id", "unknown"),
                "detail": (
                    f"{ip} aparece con una MAC distinta: "
                    f"{first_mac_by_ip[ip]} -> {mac}"
                ),
            })

    return alerts


def detect_tls(
    events: list[dict],
    expected_certs: dict
) -> list[dict]:
    alerts = []

    for event in events:
        if event.get("type") != "TLS":
            continue

        domain = event.get("sni")
        observed_fingerprint = event.get("cert_sha256")

        if domain not in expected_certs:
            continue

        expected_fingerprint = expected_certs[domain]

        if observed_fingerprint != expected_fingerprint:
            alerts.append({
                "rule": "TLS_CERT_FINGERPRINT_MISMATCH",
                "event_id": event.get("id", "unknown"),
                "detail": (
                    f"Huella inesperada para {domain}: "
                    f"esperada={expected_fingerprint}, "
                    f"observada={observed_fingerprint}"
                ),
            })

    return alerts


def analyze_file(input_path: Path) -> list[dict]:
    with input_path.open("r", encoding="utf-8") as file:
        payload = json.load(file)

    events = payload["events"]
    expected_certs = payload["expected_certs"]

    return (
        detect_dns(events)
        + detect_arp(events)
        + detect_tls(events, expected_certs)
    )


def main() -> int:
    if len(sys.argv) != 2:
        print(
            "Uso: python3 analyze.py data/sample_events.json",
            file=sys.stderr,
        )
        return 2

    input_path = Path(sys.argv[1])

    try:
        alerts = analyze_file(input_path)
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as error:
        print(f"Error al leer o analizar {input_path}: {error}", file=sys.stderr)
        return 2

    print(f"Eventos analizados: {input_path}")
    print(f"Alertas detectadas: {len(alerts)}")

    for number, alert in enumerate(alerts, start=1):
        print(
            f"[{number}] {alert['rule']} | "
            f"{alert['event_id']} | {alert['detail']}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
