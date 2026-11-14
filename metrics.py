"""Reads results/verify_<method>.json (list of {prompt_id, split, status, reasons}) and writes results/metrics.json.
Rates are over the flagged samples of each split. broken_syntax is also given over samples whose original parsed,
if the verifier adds "original_parses": true/false to each row.
Usage: python metrics.py
"""
import json
from collections import Counter
from pathlib import Path

STATUSES = ("fixed", "fake_fix", "still_insecure", "broken_syntax")
res = {}
for f in sorted(Path("results").glob("verify_*.json")):
    method = f.stem[len("verify_"):]
    rows = json.loads(f.read_text(encoding="utf-8"))
    res[method] = {}
    for split in ("dev", "test"):
        rs = [r for r in rows if r["split"] == split and r["status"] != "not_flagged"]
        c = Counter(r["status"] for r in rs)
        n = len(rs)
        m = {"n_flagged": n, **{s: c.get(s, 0) for s in STATUSES},
             **{f"{s}_rate": round(c.get(s, 0) / n, 3) if n else None for s in STATUSES}}
        parsed = [r for r in rs if r.get("original_parses")]
        if parsed:
            m["broken_syntax_rate_on_parsable"] = round(sum(r["status"] == "broken_syntax" for r in parsed) / len(parsed), 3)
        res[method][split] = m
Path("results/metrics.json").write_text(json.dumps(res, indent=1))
print(json.dumps(res, indent=1))
