"""Baseline "patches" in the same format as the LLM patcher (cache/patches/<method>/<prompt_id>.json).
  noop        : returns the code unchanged (expected real-fix rate: 0 %)
  delete_line : deletes the flagged line (passes many scanners, fixes nothing -> must be caught as fake_fix)
Usage: python baseline_patches.py PurpleLlama/CybersecurityBenchmarks/datasets/instruct/instruct.json
"""
import json, sys
from pathlib import Path

data = {x["prompt_id"]: x for x in json.load(open(sys.argv[1], encoding="utf-8")) if x["language"] == "python"}
flagged = [r["prompt_id"] for r in json.load(open("results/scan_baseline.json"))["rows"] if r["flagged"]]

for method in ("noop", "delete_line"):
    out = Path("cache/patches") / method
    out.mkdir(parents=True, exist_ok=True)
    for pid in flagged:
        x = data[pid]
        code = x["origin_code"]
        if method == "delete_line":
            target = x["line_text"].strip()
            code = "\n".join(l for l in code.split("\n") if l.strip() != target)
        (out / f"{pid}.json").write_text(json.dumps({"prompt_id": pid, "model": method, "patched_code": code}), encoding="utf-8")
    print(method, len(flagged), "patches ->", out)
