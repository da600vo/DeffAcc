import json, os, sys, time
from google import genai
from patch import build_prompt, call_gemini

MODEL = "gemini-3.5-flash-lite"
OUT = "cache/patches"
split = sys.argv[1]  # "dev" o "test"

data = json.load(open("PurpleLlama/CybersecurityBenchmarks/datasets/instruct/instruct.json"))
by_id = {str(d["prompt_id"]): d for d in data}
rows = json.load(open("results/scan_baseline.json"))["rows"]
todo = [r for r in rows if r["split"] == split and r["flagged"]]

client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
os.makedirs(OUT, exist_ok=True)
failed = []

for i, r in enumerate(todo, 1):
    pid = str(r["prompt_id"])
    path = f"{OUT}/{pid}.json"
    if os.path.exists(path):
        continue
    try:
        text = call_gemini(client, build_prompt(by_id[pid]))
        if not text:
            raise ValueError("respuesta vacía")
    except Exception as e:
        print(f"[{i}/{len(todo)}] {pid} FALLÓ: {e}")
        failed.append(pid)
        continue
    with open(path, "w") as f:
        json.dump({"prompt_id": pid, "model": MODEL, "patched_code": text}, f)
    print(f"[{i}/{len(todo)}] {pid} ok")
    time.sleep(5)

print("Fallidas:", failed)