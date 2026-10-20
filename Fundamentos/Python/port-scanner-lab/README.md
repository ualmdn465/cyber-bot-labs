# TCP Port Scanner Lab

## Problema

Los servicios de red expuestos pueden incrementar la superficie de ataque de un sistema. Este laboratorio implementa un escáner TCP connect en Python para identificar puertos accesibles en un entorno controlado.

El programa clasifica los resultados como `open`, `closed`, `filtered`, `unknown` o `error`, consulta cabeceras HTTP en puertos seleccionados y exporta los resultados a JSON.

Por defecto, solo permite el objetivo `127.0.0.1`.

## Uso (comandos)

### Preparación

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install requests
```

### Iniciar un servidor HTTP local

En una terminal independiente:

```bash
python3 -m http.server 8080 --bind 127.0.0.1
```

### Ejecutar el escaneo

```bash
python3 scan.py --host 127.0.0.1 --ports 8000-8100
```

Resultado esperado: `8080` aparece como `open` y el resto como `closed`. Por defecto, los resultados se guardan en `scan_results.json`.

### Simular un puerto filtrado

Una regla de firewall que descarta los paquetes sin responder hace que el puerto agote el timeout:

```bash
sudo iptables -A INPUT -p tcp --dport 9100 -j DROP
python3 scan.py --host 127.0.0.1 --ports 9099-9100
sudo iptables -D INPUT -p tcp --dport 9100 -j DROP
```

Resultado esperado: `9099` como `closed` (el sistema responde con RST) y `9100` como `filtered` (no hay respuesta).

### Personalizar timeout y salida

```bash
python3 scan.py --host 127.0.0.1 --ports 8080 --timeout 1 --workers 5 --output sample_output.json
```

### Ejecutar las pruebas

```bash
python3 -m unittest discover -s tests -v
```

La opción `--i-own-this-target` permite utilizar otra dirección IP, pero solo debe usarse cuando exista autorización expresa para analizar ese objetivo. `--host` debe ser una dirección IP; un nombre como `localhost` se rechaza.

## Técnica MITRE ATT&CK

**T1046 — Network Service Discovery.**

Esta técnica describe el descubrimiento de servicios de red. El laboratorio reproduce esa actividad mediante conexiones TCP para identificar servicios accesibles, exclusivamente en un entorno autorizado.

La referencia a MITRE ATT&CK sirve para relacionar el ejercicio con una técnica de descubrimiento; no implica que el script implemente todas las capacidades de esa técnica.

## Qué he aprendido

- Crear conexiones TCP con `socket`.
- Interpretar códigos de error de `connect_ex()`.
- Aplicar timeouts y limitar la concurrencia.
- Validar argumentos de línea de comandos con `argparse`.
- Consultar respuestas HTTP mediante `requests`.
- Guardar resultados estructurados en JSON.
- Escribir pruebas unitarias que simulan respuestas de red.
- Distinguir entre un puerto cerrado y una conexión que agota el tiempo de espera.
- Un timeout real con `connect_ex()` no lanza excepción: devuelve `EAGAIN`. Los tests con mocks solo prueban lo que creo que hace la librería, así que hay que contrastarlos con una prueba real.

## Posibles mejoras

- Añadir resolución DNS y soporte controlado para IPv6.
- Registrar la duración y los errores de cada intento.
- Incorporar detección de servicios mediante protocolos específicos.
- Añadir pruebas de integración con servidores locales.
- Mejorar el tratamiento de errores de conectividad y las diferencias entre sistemas operativos.
- Añadir un límite global de tiempo y una opción de cancelación.
- Incorporar un registro de auditoría para documentar el alcance autorizado de cada ejecución.

Todos los experimentos se realizan en localhost o en sistemas para los que se dispone de autorización.