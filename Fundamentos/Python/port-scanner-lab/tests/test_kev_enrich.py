import http.server
import json
import threading

import pytest

import kev_enrich


def write_json(path, data):
    """Escribe data como JSON en path y devuelve la ruta como texto."""
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


@pytest.fixture
def flaky_server():
    """Devuelve 503 dos veces y 200 en el tercer intento."""
    state = {"hits": 0}

    body = json.dumps({
        "vulnerabilities": [{
            "cveID": "CVE-2024-0001",
            "vendorProject": "Acme",
            "product": "Widget",
            "vulnerabilityName": "x",
            "dateAdded": "2024-01-01",
            "dueDate": "2024-02-01",
        }]
    }).encode()

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            state["hits"] += 1

            if state["hits"] <= 2:
                self.send_response(503)
                self.end_headers()
                return

            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = http.server.ThreadingHTTPServer(
        ("127.0.0.1", 0), Handler
    )

    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )
    thread.start()

    try:
        yield (
            f"http://127.0.0.1:{server.server_address[1]}/",
            state,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_sample_data_gives_7_findings():
    inventory = kev_enrich.load_inventory(
        "sample_data/inventory_synthetic.json"
    )
    entries = kev_enrich.load_kev(
        "sample_data/kev_sample.json"
    )

    findings = kev_enrich.find_matches(inventory, entries)

    assert len(findings) == 7
    assert "CVE-2026-33824" not in {
        finding["cve"] for finding in findings
    }


def test_no_match_word_in_middle():
    """'exchange' aparece en medio del producto del KEV: no debe coincidir.
    Falla si la regla vuelve a ser una subcadena o 'alguna palabra en común'.
    """
    ike = {
        "cveID": "CVE-2026-33824",
        "vendorProject": "Microsoft",
        "product": "Internet Key Exchange (IKE) Service Extensions",
        "vulnerabilityName": "Test",
        "dateAdded": "2024-01-01",
        "dueDate": "2024-02-01",
    }

    assert kev_enrich.matches({"vendor": "Microsoft", "product": "Exchange"}, ike) is False
    assert kev_enrich.matches({"vendor": "Microsoft", "product": "Exchange Server"}, ike) is False


def test_match_both_directions():
    # Inventario más corto que el KEV
    item = {"vendor": "Fortinet", "product": "FortiOS"}
    entry = {"vendorProject": "Fortinet", "product": "FortiOS and FortiProxy"}
    assert kev_enrich.matches(item, entry) is True

    # KEV más corto que el inventario, y con espacios sobrantes
    item = {"vendor": "Microsoft", "product": "Exchange Server"}
    entry = {"vendorProject": "Microsoft", "product": " Exchange "}
    assert kev_enrich.matches(item, entry) is True


def test_empty_kev_returns_zero_findings(tmp_path):
    kev_path = tmp_path / "empty_kev.json"
    inventory_path = tmp_path / "inventory.json"

    write_json(kev_path, {"vulnerabilities": []})
    write_json(inventory_path, [{
        "host": "host-a",
        "vendor": "Acme",
        "product": "Widget",
        "version": "1.0",
    }])

    entries = kev_enrich.load_kev(str(kev_path))
    inventory = kev_enrich.load_inventory(str(inventory_path))
    findings = kev_enrich.find_matches(inventory, entries)

    assert entries == []
    assert findings == []


def test_corrupt_json_returns_2(tmp_path, capsys):
    inventory_path = tmp_path / "inventory.json"
    kev_path = tmp_path / "corrupt_kev.json"
    output_path = tmp_path / "report.json"

    write_json(inventory_path, [{
        "host": "host-a",
        "vendor": "Acme",
        "product": "Widget",
        "version": "1.0",
    }])

    # JSON intencionadamente corrupto.
    kev_path.write_text(
        '{"vulnerabilities": [',
        encoding="utf-8",
    )

    result = kev_enrich.main([
        "--offline",
        "--inventory", str(inventory_path),
        "--kev", str(kev_path),
        "--out", str(output_path),
    ])

    captured = capsys.readouterr()

    assert result == 2
    assert "Error:" in captured.err
    assert not output_path.exists()


def test_offline_never_calls_fetch_kev(monkeypatch, tmp_path):
    inventory_path = tmp_path / "inventory.json"
    kev_path = tmp_path / "kev.json"
    output_path = tmp_path / "report.json"

    write_json(inventory_path, [])
    write_json(kev_path, {"vulnerabilities": []})

    def fail_if_called(*args, **kwargs):
        pytest.fail("fetch_kev no debe llamarse en modo offline")

    monkeypatch.setattr(
        kev_enrich,
        "fetch_kev",
        fail_if_called,
    )

    result = kev_enrich.main([
        "--offline",
        "--inventory", str(inventory_path),
        "--kev", str(kev_path),
        "--out", str(output_path),
    ])

    assert result == 0
    assert output_path.exists()


def test_retries_then_success(flaky_server, tmp_path):
    url, state = flaky_server
    destination = tmp_path / "downloaded_kev.json"

    kev_enrich.fetch_kev(
        url,
        timeout=2,
        retries=3,
        dest=str(destination),
    )

    assert state["hits"] == 3
    entries = kev_enrich.load_kev(str(destination))
    assert len(entries) == 1
    assert entries[0]["cveID"] == "CVE-2024-0001"


def test_retries_exhausted(flaky_server, tmp_path):
    url, state = flaky_server
    destination = tmp_path / "failed_kev.json"

    with pytest.raises(ValueError):
        kev_enrich.fetch_kev(
            url,
            timeout=2,
            retries=1,
            dest=str(destination),
        )

    assert state["hits"] == 2
    assert not destination.exists()
