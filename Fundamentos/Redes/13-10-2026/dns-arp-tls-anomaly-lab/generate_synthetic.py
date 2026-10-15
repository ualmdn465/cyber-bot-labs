#!/usr/bin/env python3
"""Genera eventos sintéticos y reproducibles para el laboratorio DNS/ARP/TLS."""
from pathlib import Path
import hashlib
import json
import random


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def main() -> None:
    random.seed(42)
    output = Path("data/sample_events.json")
    output.parent.mkdir(parents=True, exist_ok=True)

    expected_certs = {
        "ejemplo.test": sha256("ejemplo.test-certificado-legitimo"),
        "www.ejemplo.test": sha256("www.ejemplo.test-certificado-legitimo"),
        "tienda.test": sha256("tienda.test-certificado-legitimo"),
    }

    events = []

    # 7 eventos DNS normales: nombres legibles y TTL razonables.
    dns_records = [
        ("www.ejemplo.test", 300),
        ("mail.tienda.test", 600),
        ("api.ejemplo.test", 120),
        ("cdn.tienda.test", 900),
        ("intranet.ejemplo.test", 300),
        ("smtp.tienda.test", 600),
        ("docs.ejemplo.test", 180),
    ]
    for i, (domain, ttl) in enumerate(dns_records, start=1):
        events.append({
            "id": f"dns-normal-{i}",
            "type": "DNS",
            "timestamp": f"2026-10-15T10:{i:02d}:00Z",
            "query": domain,
            "record_type": "A",
            "ttl": ttl,
        })

    # 7 eventos ARP normales. Las IP repetidas siempre conservan su MAC.
    # MAC del rango reservado para documentación (RFC 7042): 00:00:5e:00:53:xx.
    arp_records = [
        ("192.0.2.1", "00:00:5e:00:53:01"),
        ("192.0.2.10", "00:00:5e:00:53:10"),
        ("192.0.2.20", "00:00:5e:00:53:20"),
        ("192.0.2.1", "00:00:5e:00:53:01"),
        ("192.0.2.10", "00:00:5e:00:53:10"),
        ("192.0.2.30", "00:00:5e:00:53:30"),
        ("192.0.2.20", "00:00:5e:00:53:20"),
    ]
    for i, (ip, mac) in enumerate(arp_records, start=1):
        events.append({
            "id": f"arp-normal-{i}",
            "type": "ARP",
            "timestamp": f"2026-10-15T10:{i + 10:02d}:00Z",
            "ip": ip,
            "mac": mac,
        })

    # 6 eventos TLS normales con huellas incluidas en expected_certs.
    tls_records = [
        ("ejemplo.test", expected_certs["ejemplo.test"]),
        ("www.ejemplo.test", expected_certs["www.ejemplo.test"]),
        ("tienda.test", expected_certs["tienda.test"]),
        ("ejemplo.test", expected_certs["ejemplo.test"]),
        ("www.ejemplo.test", expected_certs["www.ejemplo.test"]),
        ("tienda.test", expected_certs["tienda.test"]),
    ]
    for i, (domain, fingerprint) in enumerate(tls_records, start=1):
        events.append({
            "id": f"tls-normal-{i}",
            "type": "TLS",
            "timestamp": f"2026-10-15T11:{i:02d}:00Z",
            "sni": domain,
            "cert_sha256": fingerprint,
            "source": "proxy",
        })

    # Exactamente 3 anomalías sembradas.
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    random_subdomain = "".join(random.choice(alphabet) for _ in range(20))
    events.extend([
        {
            "id": "dns-anomaly-1",
            "type": "DNS",
            "timestamp": "2026-10-15T11:20:00Z",
            "query": f"{random_subdomain}.c2.test",
            "record_type": "A",
            "ttl": 60,
        },
        {
            "id": "arp-anomaly-1",
            "type": "ARP",
            "timestamp": "2026-10-15T11:21:00Z",
            "ip": "192.0.2.1",
            "mac": "00:00:5e:00:53:99",
        },
        {
            "id": "tls-anomaly-1",
            "type": "TLS",
            "timestamp": "2026-10-15T11:22:00Z",
            "sni": "ejemplo.test",
            "cert_sha256": sha256("ejemplo.test-certificado-falso"),
            "source": "proxy",
        },
    ])

    anomaly_count = sum(1 for event in events if "anomaly" in event["id"])

    payload = {
        "metadata": {
            "description": "Eventos totalmente sintéticos; no proceden de una red real.",
            "generated_with_seed": 42,
            "normal_event_count": len(events) - anomaly_count,
            "anomaly_count": anomaly_count,
        },
        "expected_certs": expected_certs,
        "events": events,
    }

    output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Generado: {output}")
    print(f"Eventos normales: {payload['metadata']['normal_event_count']}")
    print(f"Anomalías sembradas: {payload['metadata']['anomaly_count']}")
    print(f"Total de eventos: {len(events)}")


if __name__ == "__main__":
    main()
