"""quarantine.py: ordena la cola del especialista y arma el paquete de evidencia.

Uso (CLI), después de verify.py:
    python quarantine.py --verify results/verify_gemini.json --patches cache/patches/gemini \
        --data PurpleLlama/CybersecurityBenchmarks/datasets/instruct/instruct.json
    -> escribe results/quarantine_<método>.json

Uso (API / n8n):
    from quarantine import triage, evidence, respond
    triage(status, reasons, original_cwes) -> {route, priority, criteria}
    evidence(original, patched, findings, verify_result) -> dict
    respond(body) -> la respuesta completa de POST /quarantine (ver quarantine_api.py)

Rutas:     aprobado | parche_propuesto | cuarentena
Prioridad: P1 altamente sospechoso | P2 cuarentena | P3 parche propuesto

Un caso en cuarentena es P1 si cumple alguno de estos criterios:
    fake_fix             el parche calló al escáner y disparó una regla anti-trampa
    new_cwe              el parche trae una debilidad que el original no tenía
    critical_unresolved  queda abierta una debilidad del CWE Top 25 de MITRE (2025)
    unknown_status       estado que no conocemos: ante la duda, lo ve una persona

"Altamente sospechoso" habla del parche y de la gravedad de lo que queda abierto. No dice
que el autor del código sea malicioso: el escáner detecta prácticas inseguras, no intención.
Todo es análisis estático: NUNCA se ejecuta el código de las muestras.
"""
import argparse
import difflib
import hashlib
import json
import re
from collections import Counter
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

# Puesto en el CWE Top 25 de MITRE, edición 2025, de las debilidades que reporta el escáner.
# https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html
# CWE-798, CWE-328, CWE-338 y CWE-312 no están en esa lista: van a P2.
TOP25_RANK = {"CWE-89": 2, "CWE-78": 9, "CWE-94": 10, "CWE-502": 15}
SECRET_CWES = {"CWE-798", "CWE-312"}  # secretos escritos en el código: se tapan en la evidencia
KNOWN_QUARANTINE = {"fake_fix", "still_insecure", "broken_syntax"}
PRIORITY_ORDER = {"P1": 0, "P2": 1, "P3": 2}
MAX_DIFF_LINES = 80

# Catálogo de tipos de detección, para mostrar cada caso etapa por etapa.
CWE_NAMES = {
    "CWE-78": "Inyección de comandos del sistema operativo",
    "CWE-89": "Inyección SQL",
    "CWE-94": "Inyección de código",
    "CWE-502": "Deserialización de datos no confiables",
    "CWE-798": "Credenciales escritas en el código",
    "CWE-312": "Información sensible guardada en claro",
    "CWE-328": "Hash débil",
    "CWE-338": "Generador aleatorio débil",
}
VERIFY_DETECTIONS = {  # prefijo de la razón de verify.py -> (tipo, texto)
    "original_not_flagged": ("sin_hallazgos", "El escáner no marcó el código"),
    "patch_does_not_parse": ("sintaxis_rota", "El parche no compila"),
    "still_flagged": ("sigue_inseguro", "El escáner sigue marcando el parche"),
    "missing_definition": ("trampa", "Desapareció una función o clase del original"),
    "flagged_line_deleted": ("trampa", "La línea marcada fue borrada sin reemplazo"),
    "flagged_line_commented": ("trampa", "La línea marcada fue comentada sin reemplazo"),
    "patch_too_short": ("trampa", "El parche tiene menos de la mitad de las líneas del original"),
    "undefined_name": ("trampa", "El parche usa un nombre que nadie define"),
}
CRITERIA_TEXT = {  # prefijo del criterio de prioridad -> texto
    "fake_fix": "El parche calló al escáner sin arreglar",
    "new_cwe": "El parche trae una debilidad que el original no tenía",
    "critical_unresolved": "Queda abierta una debilidad del CWE Top 25 de MITRE 2025",
    "unknown_status": "Estado desconocido: lo decide una persona",
}

_STILL = re.compile(r"^still_flagged:(CWE-\d+)@")
_LITERAL = re.compile(r"""(["'])((?:(?!\1).){3,})\1""")


# ---------------------------------------------------------------------------
# Criterio: ruta y prioridad
# ---------------------------------------------------------------------------
def triage(status: str, reasons: list, original_cwes) -> dict:
    """Ruta y prioridad de un caso, a partir de la salida de verify().

    original_cwes: los CWE que el escáner marcó en el código original.
    """
    if status == "not_flagged":
        return {"route": "aprobado", "priority": None, "criteria": []}
    if status == "fixed":
        return {"route": "parche_propuesto", "priority": "P3", "criteria": []}

    original = set(original_cwes)
    still = {m.group(1) for r in reasons if (m := _STILL.match(r))}
    # Con trampa o sintaxis rota no hay re-escaneo útil: lo original sigue abierto.
    unresolved = (still or original) if status == "still_insecure" else original

    criteria = []
    if status == "fake_fix":
        criteria.append("fake_fix")
    if status not in KNOWN_QUARANTINE:
        criteria.append(f"unknown_status:{status}")
    if original:
        criteria += [f"new_cwe:{c}" for c in sorted(still - original)]
    criteria += [f"critical_unresolved:{c}"
                 for c in sorted(unresolved & TOP25_RANK.keys(), key=TOP25_RANK.get)]
    return {"route": "cuarentena", "priority": "P1" if criteria else "P2", "criteria": criteria}


def detections(findings: list, verify_result: dict, criteria: list) -> list:
    """Los tipos de detección de un caso, etapa por etapa: qué encontró el escáner,
    qué encontró el verificador y por qué el caso es prioridad 1."""
    out = []
    for f in findings:
        cwe = f.get("cwe")
        out.append({"stage": "escaneo", "source": "CodeShield", "type": "practica_insegura",
                    "code": cwe, "line": f.get("line"),
                    "text": CWE_NAMES.get(cwe, "Práctica insegura")})
    for r in verify_result.get("reasons") or []:
        kind, text = VERIFY_DETECTIONS.get(str(r).split(":")[0], ("otra", str(r)))
        out.append({"stage": "verificacion", "source": "verify.py", "type": kind,
                    "code": str(r), "text": text})
    for c in criteria:
        out.append({"stage": "cuarentena", "source": "quarantine.py", "type": "prioridad_1",
                    "code": c, "text": CRITERIA_TEXT.get(c.split(":")[0], c)})
    return out


def queue_key(row: dict) -> tuple:
    """Orden de la cola: prioridad, luego la debilidad más grave según el Top 25."""
    worst = min((TOP25_RANK.get(c, 99) for c in row.get("cwes", [])), default=99)
    return (PRIORITY_ORDER.get(row.get("priority"), 3), worst, str(row.get("prompt_id")))


# ---------------------------------------------------------------------------
# Paquete de evidencia
# ---------------------------------------------------------------------------
def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def scanner_versions() -> dict:
    out = {}
    for pkg in ("codeshield", "semgrep"):
        try:
            out[pkg] = version(pkg)
        except PackageNotFoundError:
            out[pkg] = None
    return out


def secret_literals(original: str, findings: list) -> list:
    """Textos entre comillas de las líneas que el escáner marcó como secreto en el código."""
    lines = original.split("\n")
    found = []
    for f in findings:
        n = f.get("line") or 0
        if f.get("cwe") in SECRET_CWES and 0 < n <= len(lines):
            found += [m.group(2) for m in _LITERAL.finditer(lines[n - 1])]
    return found


def redact(text: str, secrets: list) -> str:
    for s in sorted(set(secrets), key=len, reverse=True):
        text = text.replace(s, "***")
    return text


def evidence(original: str, patched: str, findings: list, verify_result: dict,
             model: str = None, origin: dict = None) -> dict:
    """Lo que recibe el especialista para decidir sin abrir nada más.

    findings: hallazgos del original con la forma de /scan: [{cwe, line, rule}].
    Los secretos escritos en el código se tapan: la evidencia no debe filtrarlos.
    """
    secrets = secret_literals(original, findings)
    lines = original.split("\n")

    def line_text(n):
        return redact(lines[n - 1].strip(), secrets) if n and 0 < n <= len(lines) else None

    diff = list(difflib.unified_diff(original.splitlines(), patched.splitlines(),
                                     "original", "parche", lineterm="", n=2))
    return {
        "findings": [{**{k: f.get(k) for k in ("cwe", "line", "rule", "desc") if f.get(k) is not None},
                      "line_text": line_text(f.get("line"))} for f in findings],
        "diff": [redact(l, secrets) for l in diff[:MAX_DIFF_LINES]],
        "diff_truncated": len(diff) > MAX_DIFF_LINES,
        "verify": {k: verify_result.get(k) for k in ("status", "reasons", "original_parses")},
        "redacted_secrets": len(set(secrets)),
        # Procedencia: de dónde sale cada pieza, para poder reproducir y re-revisar.
        "provenance": {
            "sha256_original": sha256(original),
            "sha256_patch": sha256(patched),
            "scanner": scanner_versions(),
            "patch_model": model,
            "origin": origin,
        },
        # La decisión es de una persona y queda con su nombre y su fecha.
        "decision": {"by": None, "at": None, "action": None, "note": None},
    }


def respond(body: dict) -> dict:
    """Respuesta de POST /quarantine. Solo usa la biblioteca estándar.

    body: {original_code, patched_code, findings, verify, model}
          findings = la lista de /scan; verify = el objeto de /verify.
    Devuelve los campos de /verify más {route, priority, criteria, detections, evidence}.
    """
    verify_result = body.get("verify") or {}
    findings = [f for f in body.get("findings") or [] if isinstance(f, dict)]
    original = body.get("original_code") or ""
    out = {k: verify_result.get(k) for k in ("status", "reasons", "original_parses")}
    out.update(triage(str(verify_result.get("status") or ""), verify_result.get("reasons") or [],
                      [f["cwe"] for f in findings if f.get("cwe")]))
    out["detections"] = detections(findings, verify_result, out["criteria"])
    out["evidence"] = evidence(original, body.get("patched_code") or original, findings,
                               verify_result, model=body.get("model"))
    return out


# ---------------------------------------------------------------------------
# CLI: cola completa de un método sobre el dataset
# ---------------------------------------------------------------------------
def dataset_finding(x: dict) -> dict:
    """El hallazgo conocido de una muestra de CyberSecEval, con la forma de /scan."""
    target = x["line_text"].strip()
    line = next((i + 1 for i, l in enumerate(x["origin_code"].split("\n")) if l.strip() == target), None)
    rule = str(x.get("pattern_id") or "").split(".")[-1] or None
    return {"cwe": x["cwe_identifier"], "line": line, "rule": rule, "desc": x.get("pattern_desc")}


def original_cwes(x: dict, row: dict) -> set:
    """CWE del original. Si el parche trae un CWE distinto al de la etiqueta, se confirma
    con el escáner oficial que de verdad sea nuevo."""
    label = {x["cwe_identifier"]}
    still = {m.group(1) for r in row["reasons"] if (m := _STILL.match(r))}
    if row["status"] == "still_insecure" and not still <= label:
        try:
            from scan_baseline import scan_code  # escáner oficial
            return label | set(scan_code(x["origin_code"]))
        except ImportError:
            print("AVISO: sin codeshield no se puede confirmar new_cwe; se usa la etiqueta del dataset")
    return label


def summarize(rows: list) -> dict:
    """Carga del especialista por partición, sobre los casos marcados."""
    res = {}
    for split in ("dev", "test"):
        rs = [r for r in rows if r["split"] == split]
        n = len(rs)
        if not n:
            continue
        pr = Counter(r["priority"] for r in rs)
        q = sum(r["route"] == "cuarentena" for r in rs)
        res[split] = {
            "n_flagged": n,
            "quarantine": q, "quarantine_rate": round(q / n, 3),
            "P1": pr["P1"], "P1_rate": round(pr["P1"] / n, 3),
            "P2": pr["P2"], "P3": pr["P3"],
            "criteria": dict(Counter(c.split(":")[0] for r in rs for c in r["criteria"])),
        }
    return res


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", required=True, help="results/verify_<método>.json")
    ap.add_argument("--patches", required=True, help="cache/patches/<método>")
    ap.add_argument("--data", required=True, help="instruct.json")
    args = ap.parse_args()

    rows = json.loads(Path(args.verify).read_text(encoding="utf-8"))
    data = {str(x["prompt_id"]): x
            for x in json.loads(Path(args.data).read_text(encoding="utf-8"))
            if x["language"] == "python"}

    queue = []
    for r in rows:
        if r["status"] == "not_flagged":
            continue
        pid = str(r["prompt_id"])
        x = data[pid]
        cwes = original_cwes(x, r)
        row = {"prompt_id": r["prompt_id"], "split": r["split"], "status": r["status"],
               "cwes": sorted(cwes), **triage(r["status"], r["reasons"], cwes)}
        if row["route"] == "cuarentena":
            pf = Path(args.patches) / f"{pid}.json"
            if pf.exists():
                p = json.loads(pf.read_text(encoding="utf-8"))
                row["evidence"] = evidence(
                    x["origin_code"], p["patched_code"], [dataset_finding(x)], r,
                    model=p.get("model"), origin={"repo": x.get("repo"), "file_path": x.get("file_path")})
            else:
                print(f"AVISO: falta el parche {pf}; el caso va sin evidencia")
        queue.append(row)
    queue.sort(key=queue_key)

    summary = summarize(queue)
    method = Path(args.verify).stem[len("verify_"):]
    out = Path("results") / f"quarantine_{method}.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({"versions": scanner_versions(), "summary": summary, "queue": queue},
                              indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"{method}: {len(queue)} casos -> {out}")
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
