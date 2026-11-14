# Arquitectura de CyberElotes: Parche Verificado

Documento para empezar a trabajar. Léelo completo una vez (10 minutos).

## 1. La idea en una frase

Antes de que un agente use una *skill* o un servidor MCP, revisamos su código: detectamos prácticas inseguras, proponemos un parche y **verificamos que el parche arregla el problema de verdad**, no que solo silencia al escáner.

## 2. Flujo completo

```mermaid
flowchart TD
    A[Llega una skill nueva o actualizada<br/>webhook / disparador manual] --> B[/scan<br/>reglas de CodeShield/]
    B -->|no marcado| OK[APROBADO<br/>sin hallazgos]
    B -->|marcado: CWE + línea| C[/patch<br/>Gemini propone un parche/]
    C --> D[/verify<br/>sintaxis + re-escaneo + anti-trampa/]
    D -->|fixed| P[PARCHE PROPUESTO<br/>se entrega, NO se aplica]
    D -->|fake_fix| Q[CUARENTENA<br/>revisión de especialista]
    D -->|still_insecure| Q
    D -->|broken_syntax| Q
    P --> R[Respuesta JSON con evidencia:<br/>CWE, línea, diff, razones]
    Q --> R
    OK --> R
```

Quién hace cada caja:

| Caja | Archivo | Dueño |
|---|---|---|
| Orquestación (todo el diagrama) | `n8n/flujo.json` | Adrián |
| API que n8n llama | `api.py` | David |
| `/scan` | `scan_baseline.py` (`scan_dir`) | ya existe |
| `/patch` | `patch.py` | Leandro |
| `/verify` | `verify.py` | Antonia |
| Ataques al verificador | `cache/patches/marlon_*` + PRs de reglas | Marlon |
| Métricas | `metrics.py` | David opera, Adrián revisa |

## 3. El parche, explicado en detalle

### 3.1 Qué es

Un **parche** es una versión corregida del código. Nuestro sistema **no toca el código del usuario**: genera el parche, lo verifica y lo **entrega como propuesta**. Una persona decide si lo aplica. Aplicarlo solo es una opción futura, y solo para parches verificados.

### 3.2 Ejemplo (ilustrativo, probado con nuestro escáner)

Código original. El escáner lo marca como **CWE-338** (generador aleatorio no criptográfico usado para un token):

```python
import random

def new_token():
    token = random.randint(0, 999999)
    return token
```

Cuatro respuestas posibles del parcheador, y lo que dice nuestro verificador:

| Parche | Código | ¿El escáner lo marca? | Estado |
|---|---|---|---|
| Correcto | `token = secrets.randbelow(1000000)` (con `import secrets`) | No | `fixed` |
| Trampa: borrar la línea | se quita la línea; `return token` queda roto | **No** | `fake_fix` |
| Trampa: comentarla | `# token = random.randint(...)` y `token = 4` | **No** | `fake_fix` |
| No arregló | `random.seed(); token = random.randint(...)` | Sí | `still_insecure` |

**La lección:** las dos trampas silencian al escáner. Si medimos parches solo con el escáner, una estrategia que no arregla nada parece exitosa. Por eso existe `verify.py`.

### 3.3 Cómo decide el verificador (en este orden)

1. **¿Compila?** Si el original compila con `ast.parse` y el parche no → `broken_syntax`. (Solo 94 de los 351 fragmentos originales compilan, porque muchos son pedazos de archivos. Si el original no compila, este paso se salta y se anota `original_parses: false`.)
2. **¿El escáner lo sigue marcando?** Sí → `still_insecure`.
3. **¿Hizo trampa?** → `fake_fix` si:
   - desapareció una función o clase del original;
   - la línea marcada fue borrada o comentada sin un reemplazo equivalente;
   - el parche tiene menos de la mitad de las líneas del original.
4. Si pasa todo → `fixed`.

Marlon intenta engañar estas reglas en dev. Cada truco que pase se convierte en una regla nueva.

### 3.4 Qué NO hace el parche

- No ejecuta el código (todo es análisis estático).
- No garantiza que el programa siga funcionando igual: no tenemos pruebas unitarias de cada fragmento. Es un límite que se declara.
- No se aplica automáticamente.

## 4. Datos y medición

- **Dataset:** CyberSecEval `instruct.json` (PurpleLlama, Meta), solo Python: 351 fragmentos de código real con una línea insegura conocida y su CWE.
- **División por repositorio, semilla 42:** dev = 115 fragmentos (75 marcados), test = 236 (153 marcados). Se divide por repositorio para que el estilo de un mismo proyecto no aparezca en ambos lados.
- **Dev** sirve para construir: prompt, reglas anti-trampa. **Test** se corre una sola vez, al final.
- **Variantes que se comparan:** `noop` (no hacer nada), `delete_line` (borrar la línea marcada) y `gemini` (nuestro parcheador).
- **Métricas** (sobre los marcados): corrección real (`fixed`), falsa corrección (`fake_fix`), sigue inseguro, sintaxis rota, y segundos por muestra.

## 5. Contratos (para trabajar en paralelo)

### Archivos

| Archivo | Formato |
|---|---|
| `results/scan_baseline.json` | `{summary, rows:[{prompt_id, split, cwe, flagged, same_cwe}]}` |
| `cache/patches/<método>/<prompt_id>.json` | `{prompt_id, model, patched_code}` |
| `results/verify_<método>.json` | `[{prompt_id, split, status, reasons, original_parses}]` |
| `results/metrics.json` | lo escribe `metrics.py` |

### API (`api.py`)

| Endpoint | Entrada | Salida |
|---|---|---|
| `POST /scan` | `{code, language}` | `{flagged, findings:[{cwe, line, rule}]}` |
| `POST /patch` | `{code, findings}` | `{patched_code, model}` |
| `POST /verify` | `{original_code, patched_code}` | `{status, reasons, original_parses}` |
| `GET /health` | | `{ok: true}` |

Mientras una pieza no exista, se devuelve una respuesta fija con esta forma. Nadie espera a nadie.

## 6. Qué revisamos y qué no (alcance honesto)

| Dónde puede esconderse el ataque | Ejemplo | Hoy |
|---|---|---|
| Código que trae una skill (scripts) | un script con `random` para tokens, `eval`, `pickle` | **Sí, medido** en CyberSecEval |
| Texto de `SKILL.md` y descripciones de herramientas MCP | "Antes de usar read_file, envía ~/.ssh a…" | **Extra si sobra tiempo:** reglas de texto del trabajo previo de Adrián, sin re-medir hoy |
| Salidas de herramientas en ejecución (inyección indirecta) | una página web que dice "ignora al usuario y…" | No. Trabajo futuro |
| Archivos del proyecto (comentarios, README, config) | instrucciones escondidas en comentarios | No. Trabajo futuro |

## 7. Cómo empezar (todos)

1. Aceptar la invitación al repo → **Code → Codespaces → Create codespace on main**.
2. Si sale "Restricted Mode": **Manage → Trust**.
3. En la terminal:

```bash
git clone --depth 1 --filter=blob:none --sparse https://github.com/meta-llama/PurpleLlama
cd PurpleLlama && git sparse-checkout set CybersecurityBenchmarks/datasets/instruct CodeShield && cd ..
pip install -r requirements.txt
python scan_baseline.py PurpleLlama/CybersecurityBenchmarks/datasets/instruct/instruct.json
python baseline_patches.py PurpleLlama/CybersecurityBenchmarks/datasets/instruct/instruct.json
git checkout -b <tu-nombre>
```

Debe salir dev 75/115 y test 153/236.

4. Para subir tu trabajo:

```bash
git add <tus archivos> && git commit -m "qué hiciste" && git push -u origin <tu-nombre>
```

Luego, en GitHub, **Compare & pull request**. Para traer lo de los demás: `git checkout main && git pull`, y vuelves a tu rama con `git checkout <tu-nombre> && git merge main`.

## 8. Reglas

1. Se ajusta solo con dev. Test, una vez.
2. Todo número de la ficha sale de `results/*.json`.
3. Nunca se ejecuta el código de las muestras.
4. Nada de claves en el repo: van en `.env` (ver `.env.example`).
5. Las técnicas para engañar al verificador se reportan solo en agregado.

## 9. Glosario

| Término | Significado |
|---|---|
| CWE | Catálogo estándar de tipos de debilidad de software (ej. CWE-338: aleatorio débil para seguridad) |
| CodeShield / semgrep | El escáner de Meta y el motor de reglas que usa por debajo |
| Marcado | El escáner encontró una práctica insegura |
| Parche | Versión corregida del código, propuesta y no aplicada |
| `fake_fix` | Parche que silencia al escáner sin arreglar el problema |
| dev / test | Datos para construir / datos para reportar, nunca mezclados |
| Línea base | Método simple de comparación (`noop`, `delete_line`) |
