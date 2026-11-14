"""
CyberElotes API: Endpoints 

Each endpoint does ONE job; the order (scan -> patch -> verify -> route) lives in n8n.
ARQUITECTURA.md sección 5.

    GET  /health                                  -> {ok}
    POST /scan    {code, language}                -> {flagged, findings:[{cwe, line, rule}]}
    POST /patch   {code, findings}                -> {patched_code, model}
    POST /verify  {original_code, patched_code}   -> {status, reasons, original_parses}

/patch and /verify return a fixed "stub" answer with the same shape until
patch.py (Leandro) and verify.py (Antonia) exist, so n8n can be built now.

Run (in the Codespace):  uvicorn api:app --reload --port 8000
Test page:               http://localhost:8000/docs
"""
import ast
import json
import subprocess
import tempfile
from pathlib import Path
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="CyberElotes API")


# --- Request / response shapes (the contract) -------------------------------

class Finding(BaseModel):
    cwe: str      # e.g. "CWE-338"
    line: int     # 1-based line in the submitted code
    rule: str     # semgrep rule id that fired


class ScanIn(BaseModel):
    code: str
    language: str = "python"


class ScanOut(BaseModel):
    flagged: bool
    findings: list[Finding]


class PatchIn(BaseModel):
    code: str
    findings: list[Finding] = []


class PatchOut(BaseModel):
    patched_code: str
    model: str


class VerifyIn(BaseModel):
    original_code: str
    patched_code: str


class VerifyOut(BaseModel):
    status: str             # fixed | fake_fix | still_insecure | broken_syntax
    reasons: list[str]
    original_parses: bool


# --- Endpoints ---------------------------------------------------------------

@app.get("/health")
def health():
    return {"ok": True}


@app.post("/scan", response_model=ScanOut)
def scan_endpoint(req: ScanIn):
    if req.language.lower() != "python":
        raise HTTPException(400, "Only Python is supported")
    findings = run_scanner(req.code)
    return ScanOut(flagged=bool(findings), findings=findings)


@app.post("/patch", response_model=PatchOut)
def patch_endpoint(req: PatchIn):
    try:
        from patch import patch as llm_patch  # Leandro's patch.py
    except ModuleNotFoundError as e:
        if e.name != "patch":  # patch.py exists but one of ITS imports failed: show that error
            raise
        return PatchOut(patched_code=req.code, model="stub")
    # TODO: confirm signature with Leandro: patch(code, findings) -> {patched_code, model}
    return llm_patch(req.code, [f.model_dump() for f in req.findings])


@app.post("/verify", response_model=VerifyOut)
def verify_endpoint(req: VerifyIn):
    try:
        from verify import verify  # Antonia's verify.py
    except ModuleNotFoundError as e:
        if e.name != "verify":
            raise
        return VerifyOut(status="fixed", reasons=["stub: verify.py not available yet"],
                         original_parses=parses(req.original_code))
    # TODO: confirm signature with Antonia: verify(original_code, patched_code) -> {status, reasons, original_parses}
    return verify(req.original_code, req.patched_code)


# --- Helpers -----------------------------------------------------------------

def run_scanner(code: str) -> list[Finding]:
    """Scan one snippet with CodeShield's Python semgrep rules (same rules as scan_baseline.py),
    keeping the line and rule id that scan_dir() drops."""
    # Imported here so /health and /docs still work where CodeShield isn't installed.
    from codeshield.insecure_code_detector import oss
    from scan_baseline import RULES

    with tempfile.TemporaryDirectory() as tmp:
        f = Path(tmp) / "snippet.py"
        f.write_text(code, encoding="utf-8")
        out = subprocess.run(
            [str(oss._make_semgrep_binary_path()), "--experimental", "--metrics", "off", "--quiet",
             "--json", "--config", str(RULES), str(f)],
            capture_output=True, text=True)
    try:
        results = json.loads(out.stdout)["results"]
    except (json.JSONDecodeError, KeyError):
        raise HTTPException(500, f"Scanner failed: {out.stderr.strip()[:500]}")
    return [Finding(cwe=str(r["extra"].get("metadata", {}).get("cwe_id", "?")),
                    line=r["start"]["line"], rule=r["check_id"])
            for r in results]


def parses(code: str) -> bool:
    try:
        ast.parse(code)
        return True
    except SyntaxError:
        return False
