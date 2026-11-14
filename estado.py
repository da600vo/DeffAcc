"""estado.py: tablero de una pantalla. Qué hay en main, qué falta por entrar y qué está en riesgo.

Uso:  python estado.py        (hace git fetch y lee todo de git; no cambia nada)
Sale en texto plano, para pegarlo en el chat del equipo.
"""
import json
import subprocess
from datetime import datetime

HITOS = [("14:45", "reglas del verificador congeladas"),
         ("14:50", "parches de test y verify de noop y delete_line en el repo"),
         ("15:00", "results/metrics.json en main"),
         ("15:30", "código congelado"),
         ("16:00", "envío"),
         ("17:00", "cierre oficial de entregas")]
PIEZAS = [("api.py", "API"), ("verify.py", "verificador"), ("patch.py", "parcheador"),
          ("quarantine.py", "cuarentena"), ("n8n/flujo.json", "flujo n8n"), ("docs/FICHA.md", "ficha"),
          ("results/verify_noop.json", "verify noop"), ("results/verify_delete_line.json", "verify delete_line"),
          ("results/verify_gemini.json", "verify gemini"), ("results/metrics.json", "métricas")]


def git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True).stdout.strip()


def main():
    git("fetch", "--quiet", "--prune", "origin")
    now = datetime.now().strftime("%H:%M")
    files = set(git("ls-tree", "-r", "--name-only", "origin/main").splitlines())
    print(f"ESTADO {now} | main en {git('log', '-1', '--format=%h %s', 'origin/main')[:70]}")

    print("\nEN MAIN")
    for path, name in PIEZAS:
        print(f"  [{'x' if path in files else ' '}] {name} ({path})")
    try:
        marcados = json.loads(git("show", "origin/main:results/scan_baseline.json"))["summary"]["test"]["flagged"]
    except (ValueError, KeyError):
        marcados = "?"
    gemini = sum(f.startswith("cache/patches/gemini/") for f in files)
    print(f"  parches de Gemini: {gemini} (test marcados: {marcados})")

    print("\nRAMAS QUE FALTAN POR ENTRAR A MAIN")
    pendientes = [b.strip() for b in git("branch", "-r", "--no-merged", "origin/main").splitlines()
                  if "HEAD" not in b]
    for b in pendientes or ["(ninguna)"]:
        if b == "(ninguna)":
            print("  (ninguna)")
            continue
        limpio = subprocess.run(["git", "merge-tree", "--write-tree", "origin/main", b],
                                capture_output=True, text=True).returncode
        estado = {0: "se mezcla limpio", 1: "CONFLICTO"}.get(limpio, "sin comprobar")
        cambios = [f for f in git("diff", "--name-only", f"origin/main...{b}").splitlines()
                   if not f.endswith((".png", ".svg", ".mmd"))]
        resumen = ", ".join(cambios[:4]) + (f" y {len(cambios) - 4} más" if len(cambios) > 4 else "")
        print(f"  {b.replace('origin/', ''):24} {estado:17} hace {git('log', '-1', '--format=%cr', b)[5:]:12} {resumen}")

    print("\nRIESGOS")
    riesgos = []
    if "verify.py" not in files:
        riesgos.append("sin verify.py en main: nadie puede medir")
    if "api.py" not in files:
        riesgos.append("sin api.py en main: la demo va con la API simulada")
    if "patch.py" in files and "def patch(" not in git("show", "origin/main:patch.py"):
        riesgos.append("patch.py no tiene patch(code, findings): /patch de la API da error 500")
    if not gemini:
        riesgos.append("sin parches de Gemini: no hay números de test para la ficha")
    if "results/metrics.json" not in files:
        riesgos.append("sin results/metrics.json: la sección 4 de la ficha sigue vacía")
    for r in riesgos or ["ninguno detectado"]:
        print(f"  - {r}")

    print("\nHITOS")
    for hora, texto in HITOS:
        marca = "vencido" if hora < now else "falta"
        print(f"  {hora}  {marca:8} {texto}")


if __name__ == "__main__":
    main()
