# Threat modeling: STRIDE + MITRE ATT&CK

Modelo de amenazas de una **tienda online ficticia** (catálogo, carrito, login, pagos con pasarela externa, formulario de asistencia y panel de administración). Se aplica STRIDE sobre un diagrama de flujo de datos y cada amenaza se mapea a una técnica de MITRE ATT&CK con su mitigación.

> Laboratorio teórico: no se ha tocado ningún sistema real y todos los datos son sintéticos.

## Problema

¿Cómo identificar y priorizar amenazas **antes de construir** una aplicación? Corregir un fallo de diseño en un diagrama cuesta mucho menos que corregirlo en producción. El threat modeling responde a cuatro preguntas (Shostack):

1. ¿En qué estamos trabajando? → Diagrama de flujo de datos (DFD) con fronteras de confianza.
2. ¿Qué puede salir mal? → STRIDE por elemento.
3. ¿Qué vamos a hacer al respecto? → Mitigaciones por amenaza.
4. ¿Lo hemos hecho bien? → Mapeo a ATT&CK y validación automática del CSV.

## Estructura

| Archivo | Contenido |
|---|---|
| [`threat-model.md`](threat-model.md) | DFD en Mermaid, tabla de amenazas STRIDE, mapeo a ATT&CK y priorización |
| [`mapping.csv`](mapping.csv) | Amenaza, categoría STRIDE, técnica ATT&CK y mitigación (datos sintéticos) |
| [`mapping_corrupto.csv`](mapping_corrupto.csv) | Copia de `mapping.csv` con un ID inválido (`t1070`) para probar el caso de error |
| [`validate_mapping.py`](validate_mapping.py) | Comprueba que cada fila del CSV tiene un ID de técnica ATT&CK con formato válido |
| `README.md` | Este documento |

## Modelo en resumen

**Componentes**

- **Entidades externas**: Cliente (E1), Administrador (E2), Pasarela de pago (E3).
- **Procesos**: Aplicación web (P1), Servicio de autenticación (P2), Panel de administración (P3).
- **Almacenes**: BD de usuarios (D1), BD de la tienda (D2), Logs (D3).

**Fronteras de confianza**

| Frontera | Separa | Motivo |
|---|---|---|
| TB1 | Internet ↔ Zona servidor | Todo lo que llega del navegador lo controla el atacante |
| TB2 | Zona servidor ↔ Zona de datos | La BD solo debe aceptar conexiones de la aplicación |
| TB3 | Zona servidor ↔ Terceros | La pasarela es externa y su webhook llega desde Internet |
| TB4 | Zona servidor ↔ Zona admin | Datos escritos por clientes llegan a la zona más privilegiada |

**Amenazas identificadas (8)**

| ID | STRIDE | Amenaza | Técnica ATT&CK |
|---|---|---|---|
| A1 | T | Manipulación del precio o la cantidad en el carrito | T1565 Data Manipulation |
| A2 | S | Suplantación del administrador con credenciales robadas | T1110 Brute Force |
| A3 | S | Webhook de pago falsificado | T1190 Exploit Public-Facing Application |
| A4 | R | Borrado de logs para ocultar acciones | T1070 Indicator Removal |
| A5 | I | Inyección SQL en el login para volcar usuarios | T1190 Exploit Public-Facing Application |
| A6 | D | Saturación del login y el carrito | T1499.003 Application Exhaustion Flood |
| A7 | E | XSS almacenado en tickets que roba la sesión del admin | T1539 Steal Web Session Cookie |
| A8 | I | Skimmer de tarjetas en el JavaScript de la web (tipo Magecart) | T1056.003 Web Portal Capture |

Las seis categorías STRIDE están cubiertas. El detalle completo (elemento, frontera y mitigación) está en `threat-model.md` y `mapping.csv`.

## Uso

```bash
python3 validate_mapping.py mapping.csv            # → código 0
python3 validate_mapping.py mapping_corrupto.csv   # → código 1, señala la línea 5
echo $?                                            # muestra el código de salida del último comando
```

| Código | Significado |
|---|---|
| `0` | Todas las filas tienen un ID de técnica válido (`T####` o `T####.###`) |
| `1` | Alguna fila tiene un ID inválido; se indica la línea |
| `2` | Error de uso o de lectura (sin argumento, archivo inexistente o sin columna `tecnica_id`) |

## Técnicas MITRE ATT&CK

| ID | Nombre | Táctica (ATT&CK v20) |
|---|---|---|
| T1565 | Data Manipulation | Impact |
| T1110 | Brute Force | Credential Access |
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1070 | Indicator Removal | Stealth |
| T1499.003 | Endpoint Denial of Service: Application Exhaustion Flood | Impact |
| T1539 | Steal Web Session Cookie | Credential Access |
| T1056.003 | Input Capture: Web Portal Capture | Collection, Credential Access |

**Notas sobre el mapeo**

- STRIDE parte del diseño y ATT&CK del comportamiento observado del atacante, así que el mapeo no es 1:1.
- **A1** es un fallo de lógica de negocio. ATT&CK no lo recoge bien y T1565 es una aproximación.
- **A3** no explota una vulnerabilidad clásica, sino la falta de verificación en un endpoint expuesto a Internet. Por eso se mapea a T1190.
- **R (repudio)** es la categoría que peor encaja, porque describe una carencia del sistema y no una acción del atacante. T1070 es lo más cercano.

## Qué he aprendido

- Un DFD modela **datos que viajan entre componentes**, no la navegación entre páginas. Al principio describí los flujos como "inicio → carrito", y eso es un mapa del sitio, no un flujo de datos.
- Las fronteras de confianza son los **bordes entre zonas**, no un recuadro por frontera. Con subgraphs anidados en Mermaid se ven las cuatro sin repetir nodos.
- La categoría STRIDE se elige por **lo que consigue el atacante** (leer → I, modificar → T, hacerse pasar por otro → S), no por el flujo donde ocurre.
- Las mitigaciones de ATT&CK son genéricas y hay que comprobar que frenan **la amenaza concreta**. Por ejemplo, cifrar no sirve contra un cliente que edita su propia petición antes de que se cifre.
- El mapeo STRIDE → ATT&CK no es 1:1: los fallos de lógica de negocio y el repudio encajan mal y hay que justificar la aproximación.
- En el script: `fullmatch` en lugar de `match` para no aceptar IDs con basura al final, y que los IDs de ATT&CK incluyen subtécnicas (`T####.###`).
- Y sobre todo, una primera toma de contacto con un sistema en el que hay que detectar las amenazas e ir proponiendo soluciones a cada una.

## Posibles mejoras

- Generar la tabla de amenazas desde un archivo YAML.
- Validar que cada ID **existe** en ATT&CK, no solo que tiene el formato correcto, descargando el dataset STIX de Enterprise ATT&CK que MITRE publica en GitHub y comprobando que la técnica no está obsoleta.
- Añadir pruebas automatizadas con unittest o pytest.
- Cuantificar la priorización de `threat-model.md` con una puntuación de probabilidad × impacto por amenaza.

## Referencias

- [MITRE ATT&CK – Enterprise Tactics](https://attack.mitre.org/tactics/enterprise/)
- [OWASP – Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [Microsoft – STRIDE en Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [Adam Shostack – Four Question Framework](https://github.com/adamshostack/4QuestionFrame)
