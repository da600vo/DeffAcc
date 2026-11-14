"""API simulada con el mismo contrato que api.py, para probar el flujo n8n
mientras la API real no existe. Solo usa la biblioteca estándar.

NO es el escáner ni el verificador reales: usa reglas mínimas para el ejemplo
CWE-78 (os.system). Ningún número de la ficha sale de aquí.

Uso:   python n8n/mock_api.py            (escucha en el puerto 8000)
Parar: pkill -f mock_api.py              (y luego: uvicorn api:app --port 8000)

Campo extra solo para la demo: /patch acepta "demo_patch" con
"fixed" | "fake_fix" | "still_insecure" para elegir qué parche simular.
La API real lo ignora.
"""
import ast
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000

RULES = [
    (re.compile(r"\bos\.system\s*\("), "CWE-78", "mock-os-system"),
    (re.compile(r"subprocess\.\w+\(.*shell\s*=\s*True"), "CWE-78", "mock-shell-true"),
]


def scan(code):
    findings = []
    for i, line in enumerate(code.splitlines(), start=1):
        if line.strip().startswith("#"):
            continue
        for rx, cwe, rule in RULES:
            if rx.search(line):
                findings.append({"cwe": cwe, "line": i, "rule": rule})
    return {"flagged": bool(findings), "findings": findings}


def parses(code):
    try:
        ast.parse(code)
        return True
    except SyntaxError:
        return False


def patch(code, findings, mode):
    lines = code.splitlines()
    for f in findings:
        idx = f["line"] - 1
        if idx < 0 or idx >= len(lines):
            continue
        line = lines[idx]
        indent = line[: len(line) - len(line.lstrip())]
        m = re.search(r"os\.system\((.*)\)\s*$", line.strip())
        arg = m.group(1) if m else None
        if mode == "fake_fix":
            lines[idx] = indent + "# " + line.strip()
        elif mode == "still_insecure" and arg:
            if arg.endswith("+ host"):
                lines[idx] = indent + "os.system(" + arg + ".strip())"
            else:
                lines[idx] = indent + "os.system((" + arg + ").strip())"
        elif arg:  # fixed
            if arg.replace(" ", "") == '"ping-c1"+host':
                new = 'subprocess.run(["ping", "-c", "1", host], check=False)'
            else:
                new = "subprocess.run(shlex.split(" + arg + "), check=False)"
                if "import shlex" not in code:
                    lines.insert(0, "import shlex")
                    idx += 1
            lines[idx] = indent + new
            if "import subprocess" not in code:
                lines.insert(0, "import subprocess")
    return {"patched_code": "\n".join(lines) + "\n", "model": "mock"}


def defs(code):
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return set()
    return {n.name for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}


def verify(original, patched):
    orig_ok = parses(original)
    reasons = []
    if orig_ok and not parses(patched):
        return {"status": "broken_syntax", "reasons": ["el parche no compila"],
                "original_parses": orig_ok}
    if scan(patched)["flagged"]:
        return {"status": "still_insecure",
                "reasons": ["el escáner sigue marcando el parche"],
                "original_parses": orig_ok}
    missing = defs(original) - defs(patched)
    if missing:
        reasons.append("desaparecieron funciones o clases: " + ", ".join(sorted(missing)))
    olines = original.splitlines()
    plines = [l.strip() for l in patched.splitlines()]
    for f in scan(original)["findings"]:
        flagged = olines[f["line"] - 1].strip()
        if "# " + flagged in plines or "#" + flagged in plines:
            reasons.append(f"línea {f['line']} comentada sin reemplazo")
        elif flagged not in plines and not any("subprocess.run(" in l for l in plines):
            reasons.append(f"línea {f['line']} borrada sin reemplazo")
    if len(patched.splitlines()) < len(olines) / 2:
        reasons.append("el parche tiene menos de la mitad de las líneas")
    if reasons:
        return {"status": "fake_fix", "reasons": reasons, "original_parses": orig_ok}
    return {"status": "fixed", "reasons": ["compila, el escáner calla y no hay trampa"],
            "original_parses": orig_ok}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"ok": True, "mock": True})
        self._send(404, {"error": "no existe"})

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(n) or b"{}")
            if self.path == "/scan":
                return self._send(200, scan(data["code"]))
            if self.path == "/patch":
                return self._send(200, patch(data["code"], data.get("findings", []),
                                             data.get("demo_patch") or "fixed"))
            if self.path == "/verify":
                return self._send(200, verify(data["original_code"], data["patched_code"]))
            self._send(404, {"error": "no existe"})
        except Exception as e:  # la demo no debe caerse por una petición mala
            self._send(400, {"error": str(e)})

    def log_message(self, fmt, *args):
        sys.stderr.write("[mock_api] " + (fmt % args) + "\n")


if __name__ == "__main__":
    print(f"mock_api escuchando en http://localhost:{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
