# TCP Port Scanner + KEV Enricher

Laboratorio local y defensivo en Python, en dos partes:

- **Escáner de puertos (9 de octubre):** escáner TCP connect limitado a loopback, con estados `open`, `closed` y `filtered`.
- **Ampliación KEV Enricher (19 de octubre):** cruza un inventario de software con el catálogo KEV de CISA para priorizar lo que tiene explotación conocida.

## Problema

**Escáner:** los servicios de red expuestos aumentan la superficie de ataque de un sistema. `scan.py` identifica los puertos accesibles en un entorno controlado, consulta cabeceras HTTP en puertos seleccionados y exporta los resultados a JSON.

**KEV Enricher:** ¿cómo priorizar hallazgos de un inventario cruzándolos con las vulnerabilidades que se están explotando activamente? Una CVE con CVSS medio que ya se explota puede ser más urgente que una crítica sin explotación conocida. `kev_enrich.py` marca qué productos del inventario aparecen en el KEV, con la fecha en que CISA confirmó la explotación y si se ha usado en campañas de ransomware.

## Estructura

```
port-scanner-lab/
├── scan.py                       # escáner TCP connect
├── kev_enrich.py                 # cruce inventario ↔ KEV
├── sample_output.json            # salida de ejemplo del escáner
├── sample_data/
│   ├── kev_sample.json           # 9 entradas reales del KEV (recorte)
│   └── inventory_synthetic.json  # inventario inventado (host-a … host-e)
└── tests/
    ├── test_scan.py              # 6 tests del escáner
    └── test_kev_enrich.py        # 8 tests del enriquecedor
```

## Uso

### Preparación

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install requests pytest
```

### Escáner de puertos

En una terminal independiente, levanta un servidor HTTP local:

```bash
python3 -m http.server 8080 --bind 127.0.0.1
```

Y escanea:

```bash
python3 scan.py --host 127.0.0.1 --ports 8000-8100
```

Resultado esperado: `8080` aparece como `open` y el resto como `closed`. Los resultados se guardan en `scan_results.json`.

Para simular un puerto **filtrado**, una regla de firewall que descarta los paquetes sin responder hace que la conexión agote el timeout:

```bash
sudo iptables -A INPUT -p tcp --dport 9100 -j DROP
python3 scan.py --host 127.0.0.1 --ports 9099-9100
sudo iptables -D INPUT -p tcp --dport 9100 -j DROP
```

Resultado esperado: `9099` como `closed` (el sistema responde con RST) y `9100` como `filtered` (no hay respuesta).

Opciones: `--timeout`, `--workers` y `--output`. `--host` debe ser una dirección IP; un nombre como `localhost` se rechaza. `--i-own-this-target` permite otra IP, y solo debe usarse con autorización expresa sobre ese objetivo.

### KEV Enricher

Con el recorte del repo, sin red:

```bash
python3 kev_enrich.py --offline --kev sample_data/kev_sample.json
```

Resultado esperado: **7 hallazgos**, ordenados de la incorporación al KEV más reciente a la más antigua.

Con el catálogo completo, descargado de CISA:

```bash
python3 kev_enrich.py
```

Descarga el KEV, lo valida y lo guarda en `kev_cache.json`. Las siguientes ejecuciones pueden usarlo sin red con `--offline` (ruta por defecto). El informe JSON se guarda en `report.json` y la tabla Markdown se imprime por pantalla.

| Opción | Por defecto | Qué hace |
|---|---|---|
| `--inventory` | `sample_data/inventory_synthetic.json` | Inventario a cruzar |
| `--kev` | `kev_cache.json` | Ruta del KEV en disco. Sin `--offline`, se descarga y se guarda aquí |
| `--kev-url` | URL oficial de CISA | Origen de la descarga |
| `--offline` | desactivado | No hace ninguna petición de red |
| `--out` | `report.json` | Informe JSON de salida |
| `--timeout` | 10 s (máx. 60) | Timeout de cada petición HTTP |
| `--retries` | 3 (de 0 a 5) | Reintentos ante errores transitorios |

Códigos de salida: `0` correcto, `1` error al escribir el informe, `2` entrada no válida o descarga fallida.

### Tests

```bash
python3 -m pytest -q
```

Ejecuta los 14 tests de los dos scripts. pytest también ejecuta los tests de `unittest` de `test_scan.py`.

## Cómo funciona el cruce con el KEV

### Regla de coincidencia

Un elemento del inventario coincide con una entrada del KEV si:

1. el **fabricante** es el mismo (`vendor` del inventario frente a `vendorProject` del KEV), y
2. la lista de palabras de un producto es **el comienzo** de la del otro, en cualquiera de las dos direcciones.

Antes de comparar, ambos textos se normalizan con `casefold()` y `split()`, que eliminan mayúsculas y espacios sobrantes. El KEV real tiene 19 productos o fabricantes con espacios al principio o al final, como `" PeopleSoft Enterprise PeopleTools"` o `"Windows "`.

| Inventario | KEV | ¿Coincide? | Motivo |
|---|---|---|---|
| Exchange Server | `Exchange Server` | Sí | Iguales |
| Exchange Server | `Exchange` | Sí | El producto del KEV es el comienzo del inventario |
| FortiOS | `FortiOS and FortiProxy` | Sí | El inventario es el comienzo del producto del KEV |
| Exchange Server | `Internet Key Exchange (IKE) Service Extensions` | No | "exchange" aparece en medio, no al principio |

Se descartaron otras dos reglas:

- **Igualdad exacta:** pierde `Exchange` frente a `Exchange Server` (falso negativo).
- **Subcadena:** "exchange" encuentra también IKE (falso positivo). `test_no_match_word_in_middle` falla si la regla vuelve a ser una subcadena.

### Limitaciones conocidas

| Limitación | Efecto |
|---|---|
| El KEV **no incluye versiones afectadas** | Todos los hallazgos son `candidate`: el producto tiene una vulnerabilidad explotada, pero no está confirmado que la versión instalada esté afectada. Hay que verificarlo con el aviso del fabricante o con los rangos CPE de NVD |
| Productos genéricos en el KEV, como `Windows` | Con el catálogo completo, `host-d` (Windows Server) acumula la mayoría de los 209 hallazgos, incluidas CVE de 2002 o 2004 que casi seguro no le afectan |
| Productos combinados en el KEV | El inventario `FortiProxy` **no** coincide con `FortiOS and FortiProxy`, porque "fortiproxy" no está al principio (falso negativo aceptado) |
| `dateAdded` no es la antigüedad de la CVE | Es la fecha en que CISA confirmó la explotación: `CVE-2008-4250` se añadió en 2026 |

### Robustez de la descarga

- **Timeout obligatorio** en cada petición, porque `requests` no tiene ninguno por defecto.
- **Reintentos limitados** con `urllib3.Retry`: solo para `GET`, solo ante 429, 500, 502, 503 y 504, y con espera creciente entre intentos (`backoff_factor=0.5`). Un 404 no se reintenta.
- **Sin `verify=False`**: se valida siempre el certificado TLS de CISA.
- **La caché no se corrompe:** la descarga se escribe en un fichero temporal, se valida con las mismas comprobaciones que el modo offline y solo entonces sustituye a `kev_cache.json` con `os.replace`. Una descarga cortada o una página HTML de error no pisan un KEV bueno.
- **Validación de la entrada:** JSON corrupto, campos obligatorios ausentes o fechas que no son `AAAA-MM-DD` exacto (`date.fromisoformat` acepta también `20240215`, que rompería la ordenación) acaban con un mensaje claro y código 2, no con una traza de Python.

## Técnica MITRE ATT&CK

Técnicas comprobadas en ATT&CK v20.

| Parte | Técnica | Táctica | Relación con el lab |
|---|---|---|---|
| Escáner | [T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046/) | Discovery | `scan.py` reproduce esta actividad, solo en loopback o con autorización. No implementa todas las capacidades de la técnica |
| KEV Enricher | [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) | Initial Access | Uso **defensivo**: el KEV recoge muchas vulnerabilidades explotadas en servicios expuestos a Internet (Exchange, FortiOS…). Priorizarlas apoya las mitigaciones M1051 Update Software y M1016 Vulnerability Scanning |

## Qué he aprendido

**Escáner (9 de octubre)**

- Crear conexiones TCP con `socket`.
- Interpretar códigos de error de `connect_ex()`.
- Aplicar timeouts y limitar la concurrencia.
- Validar argumentos de línea de comandos con `argparse`.
- Consultar respuestas HTTP mediante `requests`.
- Guardar resultados estructurados en JSON.
- Escribir pruebas unitarias que simulan respuestas de red.
- Distinguir entre un puerto cerrado y una conexión que agota el tiempo de espera.
- Un timeout real con `connect_ex()` no lanza excepción: devuelve `EAGAIN`. Los tests con mocks solo prueban lo que creo que hace la librería, así que hay que contrastarlos con una prueba real.

**KEV Enricher (19 de octubre)**

<!-- 3-4 líneas propias: timeouts y reintentos, gravedad frente a explotación, la regla de coincidencia, por qué ordenar por dateAdded de más reciente a más antiguo -->

## Posibles mejoras

**Escáner**

- Añadir resolución DNS y soporte controlado para IPv6.
- Registrar la duración y los errores de cada intento.
- Incorporar detección de servicios mediante protocolos específicos.
- Añadir pruebas de integración con servidores locales.
- Mejorar el tratamiento de errores de conectividad y las diferencias entre sistemas operativos.
- Añadir un límite global de tiempo y una opción de cancelación.
- Incorporar un registro de auditoría para documentar el alcance autorizado de cada ejecución.

**KEV Enricher**

<!-- Ideas: versiones con CPE de NVD, priorizar por ransomware antes que por fecha, puntuación EPSS, caché con ETag, salida SARIF, conectar con scan.py -->

## Datos y seguridad

- El escáner solo analiza `127.0.0.1` salvo autorización expresa.
- El inventario es **100 % inventado**: hosts `host-a` a `host-e` y versiones ficticias. `Acme Labs` es un fabricante inventado.
- `kev_sample.json` es un recorte de 9 entradas del catálogo público de CISA. Su campo `catalogVersion` indica de qué versión se extrajo.
- `kev_cache.json`, `report.json` y `scan_results.json` se generan al ejecutar y están en `.gitignore`.

## Fuentes

- [CISA – Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) y su [réplica en GitHub con el esquema JSON](https://github.com/cisagov/kev-data)
- [CISA – BOD 22-01](https://www.cisa.gov/news-events/directives/bod-22-01-reducing-significant-risk-known-exploited-vulnerabilities)
- [Python – `socket`](https://docs.python.org/3/library/socket.html), [`argparse`](https://docs.python.org/3/library/argparse.html) y [`datetime`](https://docs.python.org/3/library/datetime.html)
- [requests – uso avanzado](https://requests.readthedocs.io/en/latest/user/advanced/) y [urllib3 – `Retry`](https://urllib3.readthedocs.io/en/stable/reference/urllib3.util.html)
- [pytest](https://docs.pytest.org/)
- [Nmap – técnicas de escaneo](https://nmap.org/book/man-port-scanning-techniques.html)
- [MITRE ATT&CK T1046](https://attack.mitre.org/techniques/T1046/) y [T1190](https://attack.mitre.org/techniques/T1190/)
