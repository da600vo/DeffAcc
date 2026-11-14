# Cuarentena: criterio y paquete de evidencia

Código: `quarantine.py`. Pruebas: `tests/test_quarantine.py`. Responsable: Marlon.

## Rutas

| Estado de `verify.py` | Ruta | Prioridad |
|---|---|---|
| `not_flagged` | Aprobado | |
| `fixed` | Parche propuesto. Se entrega, no se aplica | P3 |
| `fake_fix`, `still_insecure`, `broken_syntax` | Cuarentena | P1 o P2 |
| cualquier otro estado | Cuarentena | P1: ante la duda, lo ve una persona |

## Cuándo un caso es P1 ("altamente sospechoso")

Basta con uno de estos criterios:

1. `fake_fix`: el parche calló al escáner y disparó una regla anti-trampa.
2. `new_cwe`: el parche trae una debilidad que el original no tenía.
3. `critical_unresolved`: queda abierta una debilidad del [CWE Top 25 de MITRE, edición 2025](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html): CWE-89 (puesto 2), CWE-78 (9), CWE-94 (10) o CWE-502 (15).

El resto de la cuarentena es P2. Dentro de cada prioridad, la cola se ordena por el puesto en el Top 25.

Usamos el Top 25 porque la severidad del escáner no distingue: en dev marca los 125 hallazgos como `warning`.

"Altamente sospechoso" describe el parche y la gravedad de lo que queda abierto. No afirma que el autor del código sea malicioso: el escáner detecta prácticas inseguras, no intención.

## Paquete de evidencia

Lo que recibe el especialista para decidir sin abrir nada más:

| Campo | Contenido |
|---|---|
| `findings` | CWE, línea, regla, descripción y el texto de la línea marcada |
| `diff` | Diferencia entre el original y el parche (máximo 80 líneas) |
| `verify` | Estado y razones del verificador |
| `provenance` | sha256 del original y del parche, versiones del escáner, modelo que propuso el parche, repositorio y archivo de origen. Para una skill real: autor, versión y hash anterior |
| `decision` | Vacío. Lo llena la persona que decide: quién, cuándo, qué decidió y por qué |

Los secretos escritos en el código (CWE-798 y CWE-312) se tapan con `***` en `findings` y en `diff`. `redacted_secrets` dice cuántos se taparon.

## Carga del especialista

Solo dev (85 casos marcados), con las líneas base:

| Método | Cuarentena | P1 | P2 |
|---|---|---|---|
| `noop` | 85 | 53 | 32 |
| `delete_line` | 85 | 77 | 8 |

Con el parcheador:

    python quarantine.py --verify results/verify_gemini.json --patches cache/patches/gemini --data PurpleLlama/CybersecurityBenchmarks/datasets/instruct/instruct.json

Escribe `results/quarantine_gemini.json` con el resumen (`quarantine_rate`, `P1_rate`) y la cola ordenada.

## Uso desde la API y n8n

`quarantine_api.py` expone `POST /quarantine`. En `api.py` bastan dos líneas:

    from quarantine_api import router as quarantine_router
    app.include_router(quarantine_router)

| Entrada | De dónde sale |
|---|---|
| `original_code` | El código que entró al flujo |
| `patched_code` | `/patch` |
| `findings` | `/scan` |
| `verify` | El objeto completo que devuelve `/verify` |
| `model` | `/patch` (opcional) |

Devuelve los campos de `/verify` más `{route, priority, criteria, evidence}`. En n8n va un nodo HTTP en la rama de cuarentena, entre `Estado` y `CUARENTENA`. La función `quarantine.respond(body)` hace lo mismo sin FastAPI, así que la API simulada también puede exponerlo. No cambia `/scan`, `/patch` ni `/verify`. Si el estado falta o no se reconoce, el caso sale como cuarentena P1, igual que la salida `desconocido` del nodo `Estado`.

## Límites

- La intención no se ve en el código. Se asoma en la procedencia: quién publicó la skill, de dónde viene y qué cambió entre versiones. Hoy la evidencia guarda el origen y los hashes; comparar versiones queda como trabajo futuro.
- El criterio mira el tipo de debilidad, no el contexto: un `shell=True` sobre una constante pesa igual que uno sobre entrada del usuario.
- `new_cwe` depende del mismo escáner que marcó el original.
- Solo se tapan los secretos de la línea marcada, no todos los del archivo.
- Los resultados cambian con la versión y el modo del escáner: hoy pasamos de 75 a 85 marcados en dev al cambiar al escáner oficial con semgrep 1.79.0. Por eso la evidencia guarda las versiones: una skill ya revisada debe re-revisarse cuando cambia el escáner, no solo cuando cambia su código.
- El código sale del equipo cuando se le pide el parche a Gemini. Los [términos de la capa gratuita](https://aistudio.google.com/docs/terms), vigentes desde el 23 de marzo de 2026, dicen: "Do not submit sensitive, confidential, or personal information to the Unpaid Services". Para código real: capa paga o modelo local, y tapar los secretos antes de enviar.

## Fundamentos

| Decisión de diseño | De dónde sale |
|---|---|
| La evidencia dice de dónde salió cada pieza: hashes, versiones, modelo y origen | Dignidad de datos (Jaron Lanier): una salida debe poder mostrar "the important source examples that fed into this particular output". NIST SSDF PW.4.1: obtener la procedencia de cada componente |
| La cola entrega pocas pistas ordenadas, no un volcado | Lanier propone mostrar "the top 12 sources", no todas |
| La decisión final es de una persona y queda con nombre y fecha | NIST SSDF PW.7.2: revisores expertos para buscar puertas traseras y contenido malicioso |
| P1 combina el comportamiento del parche con la clase de debilidad | Práctica de seguridad de aplicaciones: no decidir solo por severidad, y definir clases que se arreglan de inmediato, como la inyección |
| El verificador también se audita, a ciegas y por muestreo (`docs/auditoria.md`) | Control de calidad: todo inspector tiene una probabilidad de falso rechazo y otra de falsa aceptación, y se miden |
| Las líneas base son parches falsos sembrados que el verificador debe atrapar | Pruebas de mutación: un mutante que sobrevive prueba que nadie lo habría notado |
