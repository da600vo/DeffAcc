# CyberElotes: Parche Verificado

**Defensive Acceleration Hackathon 2026, Track 3: Ciberdefensa automatizada.**

Flujo automatizado que revisa el código que traen las *skills* y los servidores MCP antes de usarlos:

1. **Detecta** código inseguro y su CWE (reglas de CodeShield, PurpleLlama).
2. **Propone un parche** con un LLM (Gemini).
3. **Verifica** que el parche arregla el problema de verdad y no es una trampa que solo silencia al escáner.
4. **Enruta** cada caso (n8n): aprobado, parche propuesto o cuarentena para un especialista.

El parche **nunca se aplica solo**: se entrega como propuesta con evidencia (CWE, línea, diff y resultado del verificador).

## Evaluación

- Datos: CyberSecEval `instruct.json` (PurpleLlama), subconjunto Python (351 muestras).
- División **por repositorio**, semilla 42: dev (1/3) para construir, test (2/3) para reportar. Test se corre una sola vez.
- Líneas base: no hacer nada (`noop`) y borrar la línea marcada (`delete_line`).
- Métricas sobre los casos que el escáner marca: corrección real, falsa corrección, sigue inseguro, sintaxis rota.

Todos los números salen de `results/*.json`.

## Reproducir (GitHub Codespaces o Linux)

```bash
git clone --depth 1 --filter=blob:none --sparse https://github.com/meta-llama/PurpleLlama
cd PurpleLlama && git sparse-checkout set CybersecurityBenchmarks/datasets/instruct CodeShield && cd ..
pip install -r requirements.txt
python scan_baseline.py PurpleLlama/CybersecurityBenchmarks/datasets/instruct/instruct.json
python baseline_patches.py PurpleLlama/CybersecurityBenchmarks/datasets/instruct/instruct.json
python verify.py --patches cache/patches/delete_line --data PurpleLlama/CybersecurityBenchmarks/datasets/instruct/instruct.json
python metrics.py
```

Nota: versiones fijadas en `requirements.txt` (codeshield 1.0.1, semgrep 1.79.0). Los resultados cambian con la versión de semgrep: con 1.185 los archivos de reglas generados de CodeShield no cargan y casi nada sale marcado. `scan_baseline.py` avisa si tus versiones no coinciden.

## Estructura

| Archivo | Qué hace | Responsable |
|---|---|---|
| `scan_baseline.py` | División dev/test y escaneo de las muestras | Adrián |
| `baseline_patches.py` | Parches de las líneas base | Adrián |
| `metrics.py` | Métricas desde `results/verify_*.json` | Adrián / David |
| `verify.py` | Verificador: re-escaneo, sintaxis y reglas anti-trampa | Antonia |
| `patch.py` | Parcheador con Gemini, con caché | Leandro |
| `api.py` | API HTTP (`/scan`, `/patch`, `/verify`, `/health`) | David |
| `n8n/flujo.json` | Flujo n8n de la demo | Adrián |
| red team del verificador | Parches tramposos en dev, reportados en agregado | Marlon |

## Límites

(Por completar con resultados.) El mismo escáner que marca el problema juzga el parche; CodeShield detecta prácticas inseguras, no vulnerabilidades confirmadas; muchos fragmentos son incompletos; solo Python; el código nunca se ejecuta.

## Atribución

(Por completar.) PurpleLlama / CodeShield y CyberSecEval (Meta, ver su LICENSE), Gemini (Google), n8n, FastAPI, ayuda de asistentes de IA.
