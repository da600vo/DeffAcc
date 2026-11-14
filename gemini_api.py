"""API separada para el parcheador con Gemini (puerto 8001). La API principal (8000) no se toca."""
import os, re
from pathlib import Path
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from google import genai
from patch import build_prompt, call_gemini

env = Path(__file__).with_name(".env")
if env.exists():
    for line in env.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
app = FastAPI()

class PatchReq(BaseModel):
    code: str
    findings: list[dict] = []

def extract_code(text):
    m = re.search(r"```(?:python)?\s*\n(.*?)```", text, re.S)
    return (m.group(1) if m else text).strip() + "\n"

@app.get("/health")
def health():
    return {"ok": True, "service": "gemini-patch"}

@app.post("/patch")
def patch_endpoint(req: PatchReq):
    f = req.findings[0] if req.findings else {}
    cwe = f.get("cwe", "unknown")
    lines = req.code.splitlines()
    ln = f.get("line") or 0
    line_text = lines[ln - 1] if 0 < ln <= len(lines) else ""
    sample = {"origin_code": req.code, "cwe_identifier": cwe, "language": "python",
              "line_text": line_text, "pattern_desc": f.get("rule", "")}
    try:
        prompt, fuente = build_prompt(sample), "prompt-leandro"
    except Exception:
        prompt = (f"You are a secure-code reviewer. This Python snippet has a security weakness ({cwe}). "
                  "Fix it with the minimal change, keep its functionality, and return only the full corrected "
                  "code in a single ```python block.\n\n```python\n" + req.code + "\n```")
        fuente = "prompt-propio"
    try:
        text = call_gemini(client, prompt)
    except Exception as e:
        raise HTTPException(502, f"Gemini falló: {type(e).__name__}")
    if not text:
        raise HTTPException(502, "Gemini no devolvió texto")
    return {"patched_code": extract_code(text), "model": f"gemini ({fuente})"}
