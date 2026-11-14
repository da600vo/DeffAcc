"""
Evaluate mcp-tool-auditor on MCPTox.

Positives: 485 poisoned tool descriptions (pure_tool.json).
Negatives: clean tool descriptions of the same 45 real MCP servers
           (response_all.json -> servers -> clean_system_promot).

Split BY SERVER (fixed seed): rules were tuned on the dev servers only,
results are reported on held-out test servers the rules never saw.

Usage:
    git clone https://github.com/zhiqiangwang4/MCPTox-Benchmark
    python evaluate.py --mcptox MCPTox-Benchmark
"""
from __future__ import annotations

import argparse
import json
import random
import re
from collections import Counter, defaultdict
from pathlib import Path

from auditor import WEIGHTS, audit_tool
import auditor as A

SEED = 42
DEV_FRACTION = 1 / 3

# Baseline: the naive "jailbreak keyword" filter many quick guardrails use.
BASELINE_PATTERNS = [
    r"ignore (?:all |any )?(?:previous|prior|above) instructions", r"disregard (?:all |the )?(?:previous|above)",
    r"system prompt", r"jailbreak", r"you are now", r"developer mode", r"do anything now",
    r"forget (?:all |your )?(?:previous|prior) instructions", r"override (?:your|the) instructions",
]


def baseline_flag(text: str) -> bool:
    return any(re.search(p, text, re.IGNORECASE) for p in BASELINE_PATTERNS)


def load(mcptox: Path):
    pure = json.loads((mcptox / "pure_tool.json").read_text())
    resp = json.loads((mcptox / "response_all.json").read_text())
    servers = resp["servers"]
    tool_names = {s: v["tool_names"] for s, v in servers.items()}

    samples = []
    for entry in pure:
        for _, v in entry.items():
            srv = v["server_name"]
            samples.append({
                "server": srv, "name": v["tool_name"], "text": v["tool_content"], "label": 1,
                "paradigm": v.get("paradigm", "?"), "risk": v.get("security risk", "?"),
                "siblings": tool_names.get(srv, []) + [v["tool_name"]],
            })
    for srv, v in servers.items():
        prompt = v["clean_system_promot"]
        for chunk in prompt.split("\nTool: ")[1:]:
            name = chunk.split("\n", 1)[0].strip()
            m = re.search(r"Description:(.*?)(?:\nArguments:|\Z)", chunk, re.S)
            desc = m.group(1).strip() if m else ""
            samples.append({"server": srv, "name": name, "text": desc, "label": 0,
                            "paradigm": "-", "risk": "-", "siblings": tool_names[srv]})
    return samples


def split(samples):
    servers = sorted({s["server"] for s in samples})
    rng = random.Random(SEED)
    rng.shuffle(servers)
    dev = set(servers[: round(len(servers) * DEV_FRACTION)])
    return [s for s in samples if s["server"] in dev], [s for s in samples if s["server"] not in dev]


def metrics(y, p):
    tp = sum(1 for a, b in zip(y, p) if a and b)
    fp = sum(1 for a, b in zip(y, p) if not a and b)
    fn = sum(1 for a, b in zip(y, p) if a and not b)
    tn = sum(1 for a, b in zip(y, p) if not a and not b)
    rec = tp / (tp + fn) if tp + fn else 0
    prec = tp / (tp + fp) if tp + fp else 0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
    fpr = fp / (fp + tn) if fp + tn else 0
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn, "recall": round(rec, 3),
            "precision": round(prec, 3), "f1": round(f1, 3), "fpr": round(fpr, 3)}


def run_auditor(data, drop_rule=None):
    saved = dict(A.WEIGHTS)
    if drop_rule:
        A.WEIGHTS[drop_rule] = 0.0
    preds = [audit_tool(s["name"], s["text"], s["siblings"]).flagged for s in data]
    A.WEIGHTS.clear(); A.WEIGHTS.update(saved)
    return preds


def evasion(data):
    """Limit test: attacker refers to other tools indirectly instead of by name."""
    out = []
    for s in data:
        t = s["text"]
        if s["label"]:
            for n in s["siblings"]:
                if n != s["name"]:
                    t = re.sub(r"[`'\"]?" + re.escape(n) + r"[`'\"]?", "the other tool", t)
        out.append({**s, "text": t})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mcptox", type=Path, required=True)
    ap.add_argument("--out", type=Path, default=Path("results"))
    args = ap.parse_args()
    args.out.mkdir(exist_ok=True)

    samples = load(args.mcptox)
    dev, test = split(samples)
    res = {"dataset": {"total": len(samples), "poisoned": sum(s["label"] for s in samples),
                       "clean": sum(1 - s["label"] for s in samples),
                       "dev_servers": len({s['server'] for s in dev}),
                       "test_servers": len({s['server'] for s in test}),
                       "test_poisoned": sum(s["label"] for s in test),
                       "test_clean": sum(1 - s["label"] for s in test)}}

    for name, data in (("dev", dev), ("test", test)):
        y = [s["label"] for s in data]
        res[f"{name}_baseline"] = metrics(y, [baseline_flag(s["text"]) for s in data])
        res[f"{name}_auditor"] = metrics(y, run_auditor(data))

    y = [s["label"] for s in test]
    res["test_ablation_recall_fpr"] = {}
    for rule in WEIGHTS:
        m = metrics(y, run_auditor(test, drop_rule=rule))
        res["test_ablation_recall_fpr"][f"without_{rule}"] = {"recall": m["recall"], "fpr": m["fpr"]}

    preds = run_auditor(test)
    by = defaultdict(lambda: [0, 0])
    by_risk = defaultdict(lambda: [0, 0])
    for s, p in zip(test, preds):
        if s["label"]:
            by[s["paradigm"]][0] += p; by[s["paradigm"]][1] += 1
            by_risk[s["risk"]][0] += p; by_risk[s["risk"]][1] += 1
    res["test_recall_by_paradigm"] = {k: f"{a}/{b} ({a/b:.0%})" for k, (a, b) in sorted(by.items())}
    res["test_recall_by_risk"] = {k: f"{a}/{b} ({a/b:.0%})" for k, (a, b) in sorted(by_risk.items())}

    ev = evasion(test)
    res["test_evasion_indirect_tool_names"] = metrics([s["label"] for s in ev], run_auditor(ev))

    fps = [(s["server"], s["name"], [f.rule for f in audit_tool(s["name"], s["text"], s["siblings"]).findings])
           for s, p in zip(test, preds) if p and not s["label"]]
    res["test_false_positives"] = fps
    rule_counts = Counter()
    for s, p in zip(test, preds):
        if p and s["label"]:
            rule_counts.update(f.rule for f in audit_tool(s["name"], s["text"], s["siblings"]).findings)
    res["test_rule_frequency_in_true_positives"] = dict(rule_counts.most_common())

    (args.out / "metrics.json").write_text(json.dumps(res, indent=2, ensure_ascii=False))
    print(json.dumps({k: v for k, v in res.items() if k != "test_false_positives"}, indent=2, ensure_ascii=False))
    print(f"\nFalse positives on test: {len(fps)}")
    for f in fps:
        print("  ", f)


if __name__ == "__main__":
    main()
