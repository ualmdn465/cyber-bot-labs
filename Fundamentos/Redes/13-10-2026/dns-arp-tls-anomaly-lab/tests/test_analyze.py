"""Tests de las reglas de detección de analyze.py."""

from pathlib import Path

from analyze import (
    analyze_file,
    detect_arp,
    detect_dns,
    detect_tls,
)

# Ruta construida desde este archivo: funciona se ejecute pytest desde donde se ejecute.
SAMPLE = Path(__file__).resolve().parent.parent / "data" / "sample_events.json"


def test_dns_detecta_etiqueta_aleatoria():
    events = [
        {
            "id": "dns-test-1",
            "type": "DNS",
            "query": "hbrpoig8f1cbfno6b9m8.c2.test",
            "ttl": 60,
        }
    ]

    alerts = detect_dns(events)

    assert len(alerts) == 1
    assert alerts[0]["event_id"] == "dns-test-1"


def test_dns_ignora_nombre_normal():
    events = [
        {
            "id": "dns-test-normal",
            "type": "DNS",
            "query": "www.ejemplo.test",
            "ttl": 300,
        }
    ]

    alerts = detect_dns(events)

    assert alerts == []


def test_arp_detecta_cambio_de_mac():
    events = [
        {
            "id": "arp-1",
            "type": "ARP",
            "ip": "192.0.2.1",
            "mac": "00:00:5e:00:53:01",
        },
        {
            "id": "arp-2",
            "type": "ARP",
            "ip": "192.0.2.1",
            "mac": "00:00:5e:00:53:99",
        },
    ]

    alerts = detect_arp(events)

    assert len(alerts) == 1
    assert alerts[0]["event_id"] == "arp-2"


def test_arp_ignora_misma_mac_repetida():
    events = [
        {
            "id": "arp-normal-1",
            "type": "ARP",
            "ip": "192.0.2.1",
            "mac": "00:00:5e:00:53:01",
        },
        {
            "id": "arp-normal-2",
            "type": "ARP",
            "ip": "192.0.2.1",
            "mac": "00:00:5e:00:53:01",
        },
    ]

    alerts = detect_arp(events)

    assert alerts == []


def test_tls_detecta_huella_distinta():
    expected_certs = {
        "ejemplo.test": "huella-legitima",
    }

    events = [
        {
            "id": "tls-test-1",
            "type": "TLS",
            "sni": "ejemplo.test",
            "cert_sha256": "huella-incorrecta",
        }
    ]

    alerts = detect_tls(events, expected_certs)

    assert len(alerts) == 1
    assert alerts[0]["event_id"] == "tls-test-1"


def test_sample_events_da_tres_alertas():
    alerts = analyze_file(SAMPLE)

    assert len(alerts) == 3

    event_ids = {alert["event_id"] for alert in alerts}

    assert event_ids == {
        "dns-anomaly-1",
        "arp-anomaly-1",
        "tls-anomaly-1",
    }
