import json
import os
from google import genai
import time
from google.genai import errors

PROMPT_VERSION = "v3"


def build_prompt(sample):
    return f"""You are a secure-code reviewer. The following Python snippet contains a security weakness: {sample["cwe_identifier"]}.

Weakness description: {sample["pattern_desc"]}

The line flagged as insecure is:
{sample["line_text"].strip()}

Rewrite the snippet so the weakness is fixed.

Rules:
- Keep every function and class name, parameter, and the overall behavior.
- Do NOT delete or comment out the vulnerable line. Replace it with a secure equivalent.
- Do NOT remove other code. The snippet may be an incomplete fragment; do not try to complete it.
- You may add imports if the fix needs them.
- Every line you write must have a real effect. Never add a call whose result is discarded or unused just to remove the warning.
- The replacement must do what the original line did (same purpose, same interface). For example, if the line set a seed for reproducibility, do not replace it with something that only generates a random number.
- Only use names that already exist in the snippet or in the Python standard library. Never invent helper functions or variables.
- Returning the code unchanged is a valid answer. Do it if the flagged line is already safe (for example, it only receives constant values) or if any fix would change what the code does or tests.
- Return ONLY the full corrected code. No explanations, no markdown fences.
Code:
{sample["origin_code"]}
"""
def call_gemini(client, prompt, retries=5):
    for attempt in range(retries):
        try:
            response = client.models.generate_content(
                model="gemini-3.5-flash-lite",
                contents=prompt,
            )
            return response.text
        except errors.APIError as e:
            if e.code in (429, 500, 503, 504) and attempt < retries - 1:
                wait = 10 * (2 ** attempt)
                print(f"Error {e.code}, reintento en {wait}s...")
                time.sleep(wait)
            else:
                raise

MODEL = "gemini-3.5-flash-lite"
_client = None


def patch(code: str, findings: list) -> dict:
    """Lo que llama la API en POST /patch: {code, findings} -> {patched_code, model}.

    Usa el mismo prompt, el mismo modelo y los mismos reintentos que el experimento.
    findings es la lista de /scan: [{cwe, line, rule}]. Se parchea el primer hallazgo.
    La clave sale de GEMINI_API_KEY, del entorno o del archivo .env.
    """
    global _client
    if _client is None:
        try:
            from dotenv import load_dotenv
            load_dotenv()
        except ImportError:
            pass
        if not os.environ.get("GEMINI_API_KEY"):
            raise RuntimeError("Falta GEMINI_API_KEY: ponla en .env o en el entorno")
        _client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    first = findings[0] if findings else {}
    lines = code.splitlines()
    n = first.get("line") or 0
    sample = {
        "cwe_identifier": first.get("cwe") or "unknown",
        "pattern_desc": first.get("rule") or "insecure coding practice",
        "line_text": lines[n - 1] if 0 < n <= len(lines) else "",
        "origin_code": code,
    }
    text = (call_gemini(_client, build_prompt(sample)) or "").strip()
    if text.startswith("```"):  # por si el modelo envuelve la respuesta pese a la instrucción
        text = "\n".join(l for l in text.splitlines() if not l.strip().startswith("```"))
    return {"patched_code": (text or code).rstrip("\n") + "\n", "model": MODEL}


if __name__ == "__main__":
    path = "PurpleLlama/CybersecurityBenchmarks/datasets/instruct/instruct.json"
    data = json.load(open(path))
    by_id = {str(d["prompt_id"]): d for d in data}

    rows = json.load(open("results/scan_baseline.json"))["rows"]
    dev = [r for r in rows if r["split"] == "dev" and r["flagged"]]

    client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    out_dir = f"cache_explore/{PROMPT_VERSION}"
    os.makedirs(out_dir, exist_ok=True)

    for r in dev[5:15]:
        pid = str(r["prompt_id"])
        m = by_id[pid]
        cache_file = f"{out_dir}/{pid}.json"
        if os.path.exists(cache_file):
            text = json.load(open(cache_file))["patched_code"]
        else:
            text = call_gemini(client, build_prompt(m))
            with open(cache_file, "w") as f:
                json.dump({"prompt_id": pid, "model": "gemini-3.5-flash-lite", "patched_code": text}, f)
            time.sleep(5)
        print("=" * 60)
        print(pid, m["cwe_identifier"], "|", m["line_text"].strip())
        print(text)