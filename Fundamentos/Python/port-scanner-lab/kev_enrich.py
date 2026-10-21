#!/usr/bin/env python3

import argparse
import json
import os
import sys
from datetime import date

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


KEV_REQUIRED = (
    "cveID", "vendorProject", "product",
    "vulnerabilityName", "dateAdded", "dueDate",
)
INVENTORY_REQUIRED = ("host", "vendor", "product")
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
USER_AGENT = "kev-enrich/1.0 (laboratorio cyber-bot-labs)"


def normalize(text: str) -> list[str]:
    """Normaliza un texto y lo convierte en una lista de palabras."""
    return text.casefold().split()


def is_word_prefix(a: list[str], b: list[str]) -> bool:
    """True si la lista a es el comienzo de la lista b."""
    return b[:len(a)] == a


def matches(item: dict, entry: dict) -> bool:
    """
    item es una línea del inventario y entry una entrada del KEV.
    True si tienen el mismo fabricante y uno de los productos
    es el comienzo del otro.
    """
    if normalize(item["vendor"]) != normalize(entry["vendorProject"]):
        return False

    item_product = normalize(item["product"])
    entry_product = normalize(entry["product"])

    if not item_product or not entry_product:
        return False

    return (
        is_word_prefix(item_product, entry_product)
        or is_word_prefix(entry_product, item_product)
    )


def find_matches(inventory: list[dict], entries: list[dict]) -> list[dict]:
    """Devuelve un hallazgo por cada pareja inventario-KEV que coincide,
    ordenados por dateAdded, de más reciente a más antiguo.
    """
    findings = []

    for item in inventory:
        for entry in entries:
            if matches(item, entry):
                findings.append({
                    "host": item["host"],
                    "vendor": item["vendor"],
                    "product": item["product"].strip(),
                    "version": item.get("version", "desconocida"),
                    "cve": entry["cveID"],
                    "kev_product": entry["product"].strip(),
                    "vulnerability_name": entry["vulnerabilityName"],
                    "date_added": entry["dateAdded"],
                    "due_date": entry["dueDate"],
                    "ransomware_use": entry.get(
                        "knownRansomwareCampaignUse", "Unknown"
                    ),
                    "status": "candidate",
                })

    findings.sort(key=lambda finding: finding["date_added"], reverse=True)
    return findings


def to_markdown(findings: list[dict]) -> str:
    """Devuelve una tabla Markdown con los hallazgos."""
    lines = [
        "| Host | Producto | Producto en el KEV | Versión | CVE "
        "| Añadido al KEV | Ransomware | Estado |",
        "|---|---|---|---|---|---|---|---|",
    ]

    for finding in findings:
        lines.append(
            f"| {finding['host']} "
            f"| {finding['product']} "
            f"| {finding['kev_product']} "
            f"| {finding['version']} "
            f"| {finding['cve']} "
            f"| {finding['date_added']} "
            f"| {finding['ransomware_use']} "
            f"| {finding['status']} |"
        )

    return "\n".join(lines)


def read_json(path: str, label: str):
    """Lee un fichero JSON. Lanza ValueError con un mensaje claro si falla."""
    try:
        with open(path, encoding="utf-8") as file:
            return json.load(file)
    except OSError as exc:
        raise ValueError(f"No se puede leer {label} '{path}': {exc}") from exc
    except ValueError as exc:
        # JSONDecodeError y UnicodeDecodeError son subclases de ValueError
        raise ValueError(f"JSON no válido en {label} '{path}': {exc}") from exc


def load_kev(path: str) -> list[dict]:
    """Lee el KEV y devuelve la lista de entradas.
    Lanza ValueError si el fichero no es válido.
    """
    data = read_json(path, "el KEV")

    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise ValueError("El KEV debe ser un objeto con una lista 'vulnerabilities'.")

    entries = data["vulnerabilities"]

    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"Entrada KEV en la posición {index}: debe ser un objeto.")

        name = entry.get("cveID", f"en la posición {index}")

        for field in KEV_REQUIRED:
            if not isinstance(entry.get(field), str):
                raise ValueError(
                    f"Entrada KEV {name}: falta '{field}' o no es texto."
                )

        try:
            parsed = date.fromisoformat(entry["dateAdded"])
        except ValueError as exc:
            raise ValueError(
                f"Entrada KEV {name}: dateAdded no es una fecha válida: "
                f"{entry['dateAdded']!r}."
            ) from exc

        # fromisoformat también acepta '20240215' o '2024-W07-4', que
        # romperían la ordenación como texto: exigimos AAAA-MM-DD exacto.
        if parsed.isoformat() != entry["dateAdded"]:
            raise ValueError(
                f"Entrada KEV {name}: dateAdded debe tener el formato "
                f"AAAA-MM-DD: {entry['dateAdded']!r}."
            )

    return entries


def load_inventory(path: str) -> list[dict]:
    """Lee el inventario y devuelve sus elementos.
    Lanza ValueError si el fichero no es válido.
    """
    data = read_json(path, "el inventario")

    if not isinstance(data, list):
        raise ValueError("El inventario debe ser una lista JSON.")

    for index, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(
                f"Inventario, posición {index}: debe ser un objeto."
            )

        for field in INVENTORY_REQUIRED:
            if not isinstance(item.get(field), str):
                raise ValueError(
                    f"Inventario, posición {index}: falta '{field}' o no es texto."
                )

    return data


def fetch_kev(url: str, dest: str, timeout: float, retries: int) -> None:
    """Descarga el KEV de url y lo guarda en dest.
    Lanza ValueError con un mensaje claro si falla.
    """
    retry = Retry(
        total=retries,
        backoff_factor=0.5,                          # esperas de 0, 1, 2, 4... s
        status_forcelist=(429, 500, 502, 503, 504),  # errores transitorios
        allowed_methods=frozenset({"GET"}),          # solo métodos idempotentes
        raise_on_status=False,                       # al agotar, devuelve la respuesta
    )
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.mount("http://", HTTPAdapter(max_retries=retry))

    try:
        with session:
            response = session.get(url, timeout=timeout)
            response.raise_for_status()
            content = response.content
    except requests.RequestException as exc:
        raise ValueError(f"No se pudo descargar el KEV de {url}: {exc}") from exc

    # Se escribe en un temporal y se valida antes de sustituir la caché:
    # una descarga cortada o una página de error no pisan un KEV bueno.
    tmp = dest + ".tmp"
    try:
        with open(tmp, "wb") as file:
            file.write(content)
        try:
            load_kev(tmp)
        except ValueError as exc:
            raise ValueError(f"Lo descargado de {url} no es un KEV válido: {exc}") from exc
        os.replace(tmp, dest)
    except OSError as exc:
        raise ValueError(f"No se pudo guardar el KEV en '{dest}': {exc}") from exc
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Cruza un inventario con el catálogo KEV de CISA."
    )
    parser.add_argument(
        "--inventory", default="sample_data/inventory_synthetic.json",
        help="JSON del inventario (por defecto: %(default)s)",
    )
    parser.add_argument(
        "--kev", default="kev_cache.json",
        help="Ruta del KEV en disco. Sin --offline, se descarga y se guarda aquí "
             "(por defecto: %(default)s)",
    )
    parser.add_argument(
        "--kev-url", default=KEV_URL,
        help="URL de descarga del KEV (por defecto: la de CISA)",
    )
    parser.add_argument(
        "--offline", action="store_true",
        help="No descarga nada: lee el KEV de --kev",
    )
    parser.add_argument(
        "--out", default="report.json",
        help="Informe JSON de salida (por defecto: %(default)s)",
    )
    parser.add_argument(
        "--timeout", type=float, default=10.0,
        help="Timeout HTTP en segundos (por defecto: %(default)s)",
    )
    parser.add_argument(
        "--retries", type=int, default=3,
        help="Reintentos ante errores transitorios (por defecto: %(default)s)",
    )

    args = parser.parse_args(argv)

    if not 0 < args.timeout <= 60:
        parser.error("--timeout debe ser mayor que 0 y como máximo 60.")
    if not 0 <= args.retries <= 5:
        parser.error("--retries debe estar entre 0 y 5.")

    return args


def main(argv=None) -> int:
    args = parse_args(argv)

    try:
        inventory = load_inventory(args.inventory)
        if not args.offline:
            fetch_kev(args.kev_url, args.kev, args.timeout, args.retries)
        entries = load_kev(args.kev)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if not entries:
        print("Aviso: el KEV no tiene entradas; 0 hallazgos no significa "
              "que no haya riesgo.", file=sys.stderr)

    findings = find_matches(inventory, entries)
    print(to_markdown(findings))

    try:
        with open(args.out, "w", encoding="utf-8") as file:
            json.dump(findings, file, indent=2, ensure_ascii=False)
    except OSError as exc:
        print(f"Error al guardar {args.out}: {exc}", file=sys.stderr)
        return 1

    print(f"\nTotal de hallazgos: {len(findings)}")
    print(f"Informe JSON guardado en {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
