"""
CyberElotes API: Endpoints

Each endpoint does ONE job; the order (scan -> patch -> verify -> route) lives in n8n.
ARQUITECTURA.md sección 5.

    GET  /health                                  -> {ok, versions, skillspector}
    POST /scan    {code, language}                -> {flagged, findings:[{cwe, line, rule}]}
    POST /patch   {code, findings}                -> {patched_code, model}
    POST /verify  {original_code, patched_code}   -> {status, reasons, original_parses}
    POST /inspect {code, language}                -> {status, recommendation, findings, seconds}

/scan uses the OFFICIAL scanner: CodeShield's Insecure Code Detector (ICD), the same call as
scan_baseline.scan_code(), so the API flags exactly what the evaluation flags. It drives routing.

/inspect is an EXTRA layer (defence in depth, NOT evaluated): NVIDIA SkillSpector in static mode
(--no-llm, nothing leaves the machine) looks for MALICIOUS behaviour that CodeShield does not cover
(secrets sent to the network, credential files...). Its findings are only added to the evidence:
they do not change routing or metrics. It never fails the flow: if SkillSpector is missing, times
out or crashes, it answers normally with status unavailable | timeout | error and no findings.
Known false positive: legitimate authenticated API calls (a token from os.environ sent in a header)
come out DO_NOT_INSTALL.

/patch and /verify return a fixed "stub" answer with the same shape until
patch.py (Leandro) and verify.py (Antonia) exist, so n8n can be built now.

Needs the pinned versions in requirements.txt (codeshield 1.0.1, semgrep 1.79.0):
results change with the semgrep version. GET /health shows the versions in use.
SkillSpector lives in its OWN environment (requirements-skillspector.txt); set SKILLSPECTOR_BIN
if it is not at ~/.venvs/skillspector/bin/skillspector.

Run (Linux / WSL / Codespace):  uvicorn api:app --reload --port 8000
Test page:                      http://localhost:8000/docs
Keep the endpoints as plain `def`: ICD is called with asyncio.run(), which fails inside `async def`.
"""
import ast
import asyncio
import json
import logging
import os
import subprocess
import tempfile
import textwrap
import time
import warnings
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="CyberElotes API")
log = logging.getLogger("uvicorn.error")

# Pinned versions: taken from scan_baseline.py when it has them (main), so there is one source of truth.
try:
    from scan_baseline import EXPECTED as PINNED_VERSIONS
except ImportError:
    PINNED_VERSIONS = {"codeshield": "1.0.1", "semgrep": "1.79.0"}

SKILLSPECTOR_BIN = os.environ.get("SKILLSPECTOR_BIN",
                                  str(Path.home() / ".venvs/skillspector/bin/skillspector"))
SKILLSPECTOR_TIMEOUT = 30  # seconds; a scan normally takes ~5 s. Past this, /inspect gives up.
SCRIPT_NAME = "skill.py"
# SkillSpector scans skill FOLDERS, so the code is wrapped in a minimal skill. Findings about this
# generated SKILL.md (e.g. "no permissions declared") are ours, not the user's, and are dropped.
WRAPPER_SKILL_MD = ("---\nname: submitted-skill\ndescription: Skill submitted for security review.\n---\n\n"
                    f"# Submitted skill\n\nSee {SCRIPT_NAME}.\n")


def installed_versions() -> dict:
    out = {}
    for pkg in PINNED_VERSIONS:
        try:
            out[pkg] = version(pkg)
        except PackageNotFoundError:
            out[pkg] = None
    return out


def skillspector_available() -> bool:
    return os.access(SKILLSPECTOR_BIN, os.X_OK)


if installed_versions() != PINNED_VERSIONS:
    log.warning("Scanner versions %s differ from pinned %s: results will not match the evaluation. "
                "Run: pip install -r requirements.txt", installed_versions(), PINNED_VERSIONS)
if not skillspector_available():
    log.warning("SkillSpector not found at %s: /inspect will answer status=unavailable. "
                "See requirements-skillspector.txt or set SKILLSPECTOR_BIN.", SKILLSPECTOR_BIN)


# --- Request / response shapes (the contract) -------------------------------

class Finding(BaseModel):
    cwe: str                 # e.g. "CWE-94"
    line: int | None = None  # 1-based line in the submitted code
    rule: str                # ICD pattern id, e.g. "insecure-eval-use"


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
    status: str             # fixed | fake_fix | still_insecure | broken_syntax | not_flagged
    reasons: list[str]
    original_parses: bool


# /inspect (extra evidence, outside the contract's routing)

class InspectFinding(BaseModel):
    rule: str                       # SkillSpector rule id, e.g. "E2"
    line: int | None = None         # 1-based line in the submitted code
    severity: str | None = None     # LOW | MEDIUM | HIGH | CRITICAL
    category: str | None = None     # e.g. "Data Exfiltration"
    explanation: str | None = None  # why it matters


class InspectOut(BaseModel):
    status: str                     # ok | unavailable | timeout | error
    recommendation: str | None      # SAFE | CAUTION | DO_NOT_INSTALL (None unless status == ok)
    findings: list[InspectFinding]
    seconds: float
    detail: str | None = None       # why, when status != ok
    note: str = "Defence in depth, not evaluated: evidence only, does not change routing or metrics."


# --- Endpoints ---------------------------------------------------------------

@app.get("/health")
def health():
    current = installed_versions()
    return {"ok": True, "versions": current, "versions_match_pinned": current == PINNED_VERSIONS,
            "skillspector": {"available": skillspector_available(), "path": SKILLSPECTOR_BIN}}


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
    # Signature confirmed in Antonia's verify.py: verify(original, patched) -> {status, reasons, original_parses}
    return verify(req.original_code, req.patched_code)


@app.post("/inspect", response_model=InspectOut)
def inspect_endpoint(req: ScanIn):
    if req.language.lower() != "python":
        raise HTTPException(400, "Only Python is supported")
    return run_skillspector(req.code)


# --- Helpers -----------------------------------------------------------------

def run_scanner(code: str) -> list[Finding]:
    """Scan one snippet with CodeShield's ICD: same detector and call as scan_baseline.scan_code(),
    but keeping the line and pattern id that scan_code() drops."""
    # Imported here so /health and /docs still work where CodeShield isn't installed.
    from codeshield.insecure_code_detector import insecure_code_detector as icd
    from codeshield.insecure_code_detector.languages import Language

    try:
        issues = asyncio.run(icd.analyze(Language.PYTHON, code))
    except Exception as e:
        raise HTTPException(500, f"Scanner failed: {type(e).__name__}: {str(e)[:500]}")
    return [Finding(cwe=str(i.cwe_id), line=i.line, rule=str(i.pattern_id or i.rule or "?"))
            for i in issues]


def run_skillspector(code: str) -> InspectOut:
    """Scan the code as a skill with NVIDIA SkillSpector (static mode, no LLM).
    Never raises: any problem becomes status unavailable | timeout | error, so the flow keeps going."""
    t0 = time.monotonic()

    def done(status, recommendation=None, findings=(), detail=None):
        return InspectOut(status=status, recommendation=recommendation, findings=list(findings),
                          seconds=round(time.monotonic() - t0, 2), detail=detail)

    if not skillspector_available():
        return done("unavailable", detail=f"SkillSpector not found at {SKILLSPECTOR_BIN}")
    try:
        with tempfile.TemporaryDirectory() as tmp:
            skill = Path(tmp) / "submitted-skill"
            skill.mkdir()
            (skill / "SKILL.md").write_text(WRAPPER_SKILL_MD, encoding="utf-8")
            (skill / SCRIPT_NAME).write_text(code, encoding="utf-8")
            report_path = Path(tmp) / "report.json"
            proc = subprocess.run(
                [SKILLSPECTOR_BIN, "scan", str(skill), "--no-llm", "--format", "json", "--output", str(report_path)],
                capture_output=True, text=True, timeout=SKILLSPECTOR_TIMEOUT)
            # Exit code 1 means "risky skill found", not a crash: judge by whether a report was written.
            if not report_path.exists():
                return done("error", detail=f"exit {proc.returncode}: {proc.stderr.strip()[-300:]}")
            report = json.loads(report_path.read_text(encoding="utf-8"))
    except subprocess.TimeoutExpired:
        return done("timeout", detail=f"SkillSpector took more than {SKILLSPECTOR_TIMEOUT} s")
    except Exception as e:  # evidence is optional: never break the flow
        return done("error", detail=f"{type(e).__name__}: {str(e)[:300]}")

    findings, seen = [], set()
    for i in report.get("issues", []):
        loc = i.get("location") or {}
        if Path(str(loc.get("file", ""))).name != SCRIPT_NAME:
            continue  # about our generated SKILL.md, not the user's code
        key = (i.get("id"), loc.get("start_line"))
        if key in seen:  # SkillSpector can report the same rule twice on one line
            continue
        seen.add(key)
        findings.append(InspectFinding(rule=str(i.get("id", "?")), line=loc.get("start_line"),
                                       severity=i.get("severity"), category=i.get("category"),
                                       explanation=i.get("explanation")))
    return done("ok", report.get("risk_assessment", {}).get("recommendation"), findings)
    

def parses(code: str) -> bool:
    """Same check as verify.parses(): dedent first, many snippets are indented fragments."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            ast.parse(textwrap.dedent(code))
        return True
    except (SyntaxError, ValueError):
        return False
