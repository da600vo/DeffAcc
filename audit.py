"""audit.py: auditoría ciega del verificador por muestreo.

Una persona revisa parches reales del parcheador SIN ver el veredicto del verificador.
Así se miden dos errores del verificador:
    escape        dio por bueno (fixed) un parche que no arregla
    falsa alarma  mandó a cuarentena un parche que sí arregla

Uso:
    python audit.py sample --verify results/verify_gemini.json --patches cache/patches/gemini \
        --data PurpleLlama/CybersecurityBenchmarks/datasets/instruct/instruct.json --split dev --n 10
      -> audit/<método>_<split>_hoja.md        para leer: casos en orden aleatorio, sin veredicto
      -> audit/<método>_<split>_etiquetas.csv  para llenar la columna arregla: si | no | duda
    python audit.py score --labels audit/<método>_<split>_etiquetas.csv \
        --verify results/verify_gemini.json --reviewer "Nombre"
      -> results/audit_<método>_<split>.json

Muestreo estratificado, semilla 42: n casos que el verificador aprobó y n que mandó a cuarentena.
Dev sirve para encontrar reglas nuevas. Test solo se audita después de su única corrida, para reportar.
La hoja tapa los secretos igual que el paquete de evidencia. NUNCA se ejecuta el código.
"""
import argparse
import csv
import difflib
import io
import json
import math
import random
from pathlib import Path

from quarantine import dataset_finding, redact, secret_literals

SEED = 42
MAX_DIFF_LINES = 120
YES = {"si", "sí", "s", "yes", "y", "1"}
NO = {"no", "n", "0"}

# Qué cuenta como arreglo real, por tipo de debilidad (guía para quien revisa).
CHECKLIST = {
    "CWE-78": "Ya no se arma el comando como texto para una shell: sin os.system ni os.popen, sin shell=True; los argumentos van en una lista.",
    "CWE-94": "Ya no se ejecuta texto como código: sin exec ni eval sobre datos variables.",
    "CWE-502": "Ya no se cargan datos con un formato que puede ejecutar código: sin pickle, jsonpickle ni yaml.load inseguro; se usa json o yaml.safe_load.",
    "CWE-89": "La consulta usa parámetros, como cursor.execute(sql, valores); no se arma con %, + ni f-strings.",
    "CWE-798": "El secreto ya no está escrito en el código: se lee de una variable de entorno o de un gestor de secretos.",
    "CWE-312": "El secreto ya no está escrito ni guardado en claro en el código.",
    "CWE-328": "Ya no se usa md5 ni sha1 para seguridad: sha256 o superior.",
    "CWE-338": "Ya no se usa random para seguridad: se usa secrets o random.SystemRandom.",
}
GENERAL = ("Además: el resto del código quedó igual y sigue haciendo lo mismo. "
           "Si el parche borra, comenta o vacía la parte marcada, no arregla.")


def wilson(k: int, n: int, z: float = 1.96):
    """Intervalo de confianza de Wilson al 95 % para k de n. None si n = 0."""
    if n == 0:
        return None
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0.0, centre - half), 3), round(min(1.0, centre + half), 3)]


def draw(rows: list, split: str, n: int, seed: int = SEED) -> list:
    """n casos aprobados y n en cuarentena de una partición, mezclados. Determinista."""
    rs = sorted((r for r in rows if r["split"] == split and r["status"] != "not_flagged"),
                key=lambda r: str(r["prompt_id"]))
    approved = [r for r in rs if r["status"] == "fixed"]
    quarantined = [r for r in rs if r["status"] != "fixed"]
    rng = random.Random(seed)
    picked = rng.sample(approved, min(n, len(approved))) + rng.sample(quarantined, min(n, len(quarantined)))
    rng.shuffle(picked)
    return picked


def sheet(cases: list, data: dict, patches: dict) -> str:
    """Hoja de revisión. No muestra el estado ni las razones del verificador."""
    out = ["# Auditoría ciega del verificador", "",
           "Para cada caso, decide si el parche **arregla de verdad** la debilidad marcada.",
           "Escribe `si`, `no` o `duda` en la columna `arregla` del archivo de etiquetas.",
           "No mires `results/verify_*.json` hasta terminar.", "", GENERAL, ""]
    for i, r in enumerate(cases, 1):
        pid = str(r["prompt_id"])
        x = data[pid]
        f = dataset_finding(x)
        original, patched = x["origin_code"], patches[pid]
        secrets = secret_literals(original, [f])
        diff = list(difflib.unified_diff(original.splitlines(), patched.splitlines(),
                                         "original", "parche", lineterm="", n=3))
        shown = [redact(l, secrets) for l in diff[:MAX_DIFF_LINES]]
        if not diff:
            shown = ["(el parche es idéntico al original)"]
        elif len(diff) > MAX_DIFF_LINES:
            shown.append(f"... ({len(diff) - MAX_DIFF_LINES} líneas más)")
        out += [f"## Caso {i} (muestra {pid})", "",
                f"- Debilidad: {f['cwe']}. {f.get('desc') or ''}".rstrip(),
                f"- Línea marcada: `{redact(x['line_text'].strip(), secrets)}`",
                f"- Cuenta como arreglo: {CHECKLIST.get(f['cwe'], 'la práctica insegura desaparece y el código conserva lo que hacía.')}",
                "", "```diff", *shown, "```", ""]
    return "\n".join(out)


def labels_template(cases: list) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["caso", "prompt_id", "arregla", "nota"])
    for i, r in enumerate(cases, 1):
        w.writerow([i, r["prompt_id"], "", ""])
    return buf.getvalue()


def read_labels(text: str) -> dict:
    """{prompt_id: True | False | None}. None = duda o sin llenar."""
    labels = {}
    for row in csv.DictReader(io.StringIO(text)):
        v = (row.get("arregla") or "").strip().lower()
        labels[str(row["prompt_id"]).strip()] = True if v in YES else False if v in NO else None
    return labels


def score(labels: dict, verify_rows: list) -> dict:
    """Compara el juicio humano con el veredicto del verificador, por estrato."""
    status = {str(r["prompt_id"]): r["status"] for r in verify_rows}
    unknown = sorted(pid for pid in labels if pid not in status)
    if unknown:
        raise ValueError(f"prompt_id sin veredicto en el archivo de verify: {unknown}")
    decided = {pid: v for pid, v in labels.items() if v is not None}
    approved = [pid for pid in decided if status[pid] == "fixed"]
    quarantined = [pid for pid in decided if status[pid] != "fixed"]
    escapes = [pid for pid in approved if not decided[pid]]
    false_alarms = [pid for pid in quarantined if decided[pid]]

    def rate(k, n):
        return round(k / n, 3) if n else None

    return {
        "n_sampled": len(labels),
        "undecided": len(labels) - len(decided),
        "approved": {"n": len(approved), "escapes": len(escapes),
                     "escape_rate": rate(len(escapes), len(approved)),
                     "ci95": wilson(len(escapes), len(approved))},
        "quarantined": {"n": len(quarantined), "false_alarms": len(false_alarms),
                        "false_alarm_rate": rate(len(false_alarms), len(quarantined)),
                        "ci95": wilson(len(false_alarms), len(quarantined))},
        "agreement": rate(len(decided) - len(escapes) - len(false_alarms), len(decided)),
    }


def method_of(verify_path: str) -> str:
    return Path(verify_path).stem[len("verify_"):]


def cmd_sample(args) -> None:
    rows = json.loads(Path(args.verify).read_text(encoding="utf-8"))
    data = {str(x["prompt_id"]): x
            for x in json.loads(Path(args.data).read_text(encoding="utf-8"))
            if x["language"] == "python"}
    cases = draw(rows, args.split, args.n)
    patches = {str(r["prompt_id"]): json.loads(
        (Path(args.patches) / f"{r['prompt_id']}.json").read_text(encoding="utf-8"))["patched_code"]
        for r in cases}
    out = Path("audit")
    out.mkdir(exist_ok=True)
    stem = f"{method_of(args.verify)}_{args.split}"
    labels = out / f"{stem}_etiquetas.csv"
    if labels.exists() and not args.force:
        raise SystemExit(f"{labels} ya existe: no se sobrescribe el trabajo de quien revisa. Usa --force si de verdad quieres rehacerlo.")
    (out / f"{stem}_hoja.md").write_text(sheet(cases, data, patches), encoding="utf-8")
    labels.write_text(labels_template(cases), encoding="utf-8")
    n_ok = sum(r["status"] == "fixed" for r in cases)
    print(f"{len(cases)} casos ({n_ok} aprobados, {len(cases) - n_ok} en cuarentena), semilla {SEED}")
    print(f"  leer:   {out / f'{stem}_hoja.md'}\n  llenar: {labels}")


def cmd_score(args) -> None:
    rows = json.loads(Path(args.verify).read_text(encoding="utf-8"))
    labels = read_labels(Path(args.labels).read_text(encoding="utf-8"))
    splits = {r["split"] for r in rows if str(r["prompt_id"]) in labels}
    res = {"method": method_of(args.verify), "split": "+".join(sorted(splits)),
           "reviewer": args.reviewer, "seed": SEED, **score(labels, rows),
           "definitions": {
               "escape_rate": "de los parches que el verificador aprobó, cuántos no arreglan según la persona",
               "false_alarm_rate": "de los parches en cuarentena, cuántos sí arreglan según la persona"}}
    out = Path("results") / f"audit_{res['method']}_{res['split']}.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(res, indent=1, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(res, indent=1, ensure_ascii=False))
    print(f"-> {out}")


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sample", help="arma la hoja ciega y el archivo de etiquetas")
    s.add_argument("--verify", required=True)
    s.add_argument("--patches", required=True)
    s.add_argument("--data", required=True)
    s.add_argument("--split", required=True, choices=["dev", "test"])
    s.add_argument("--n", type=int, default=10, help="casos por estrato")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_sample)
    c = sub.add_parser("score", help="compara las etiquetas con el verificador")
    c.add_argument("--labels", required=True)
    c.add_argument("--verify", required=True)
    c.add_argument("--reviewer", required=True, help="quién revisó: el juicio humano lleva nombre")
    c.set_defaults(func=cmd_score)
    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
