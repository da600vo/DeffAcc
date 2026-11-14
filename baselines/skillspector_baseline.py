"""
Baseline: NVIDIA SkillSpector (static mode, --no-llm) on MCPTox.

SkillSpector scans agent *skills* (SKILL.md), not MCP manifests, so each
MCPTox tool description is wrapped as a minimal SKILL.md: the description
goes in the frontmatter `description` field and in the body. Same server
split as evaluate.py. This is SkillSpector outside its home turf: report it
that way.

Requirements: Python 3.12+, SkillSpector installed in its own environment:
    uv venv ssvenv && uv pip install --python ssvenv/bin/python git+https://github.com/NVIDIA/skillspector

Usage:
    python baselines/skillspector_baseline.py --mcptox MCPTox-Benchmark \
        --skillspector ssvenv/bin/skillspector --work /tmp/ss_work
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import evaluate as E  # noqa: E402

BATCH = 25  # SkillSpector's recursive scan stops at an aggregate limit of about 30 skills


def wrap(samples, work: Path):
    skills = work / "skills"
    if skills.exists():
        shutil.rmtree(skills)
    skills.mkdir(parents=True)
    dev, test = E.split(samples)
    index = {}
    for split_name, data in (("dev", dev), ("test", test)):
        for i, s in enumerate(data):
            sid = f"{split_name}-{i:04d}"
            d = skills / f"b{len(index) // BATCH:03d}" / sid
            d.mkdir(parents=True)
            desc = s["text"].replace("\r", "")
            block = "\n".join("  " + line for line in desc.split("\n"))
            name = "".join(c if c.isalnum() or c in "-_" else "-" for c in s["name"])[:60] or "tool"
            (d / "SKILL.md").write_text(
                f"---\nname: {name}\ndescription: |\n{block}\n---\n\n# {name}\n\n{desc}\n", encoding="utf-8")
            index[sid] = {"split": split_name, "label": s["label"], "paradigm": s["paradigm"]}
    return skills, index


def scan(skills: Path, binary: str):
    results = {}
    for batch in sorted(p for p in skills.iterdir() if p.is_dir()):
        out = batch.with_suffix(".json")
        subprocess.run([binary, "scan", str(batch), "--recursive", "--no-llm", "--format", "json",
                        "--output", str(out)], capture_output=True, text=True)
        report = json.loads(out.read_text())
        if report.get("skills_omitted"):
            raise SystemExit(f"SkillSpector omitted skills in {batch}; lower BATCH")
        for s in report["skills"]:
            ra = s.get("risk_assessment", {})
            results[s["path"]] = {"rec": ra.get("recommendation"), "findings": s.get("finding_count", 0),
                                  "rules": sorted({i["id"] for i in s.get("issues", [])})}
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mcptox", type=Path, required=True)
    ap.add_argument("--skillspector", default="skillspector")
    ap.add_argument("--work", type=Path, default=Path("/tmp/ss_work"))
    ap.add_argument("--out", type=Path, default=Path("results"))
    args = ap.parse_args()

    samples = E.load(args.mcptox)
    skills, index = wrap(samples, args.work)
    res = scan(skills, args.skillspector)
    assert len(res) == len(index), f"scanned {len(res)} of {len(index)}"

    report = {"tool": "NVIDIA SkillSpector, static mode (--no-llm)", "input": "MCPTox descriptions wrapped as SKILL.md"}
    rules = {
        "caution_or_worse": lambda v: v["rec"] != "SAFE",
        "any_finding": lambda v: v["findings"] > 0,
        "do_not_install": lambda v: v["rec"] == "DO_NOT_INSTALL",
    }
    for split in ("dev", "test"):
        rows = [(index[k], v) for k, v in res.items() if index[k]["split"] == split]
        y = [a["label"] for a, _ in rows]
        for rname, f in rules.items():
            report[f"{split}_{rname}"] = E.metrics(y, [f(v) for _, v in rows])
    test_rows = [(index[k], v) for k, v in res.items() if index[k]["split"] == "test"]
    report["test_rules_on_poisoned"] = dict(Counter(r for a, v in test_rows if a["label"] for r in v["rules"]).most_common())
    report["test_rules_on_clean"] = dict(Counter(r for a, v in test_rows if not a["label"] for r in v["rules"]).most_common())
    report["recommendations_all"] = dict(Counter(v["rec"] for v in res.values()))

    args.out.mkdir(exist_ok=True)
    (args.out / "skillspector.json").write_text(json.dumps(report, indent=2))
    print(json.dumps({k: v for k, v in report.items() if k.startswith("test_")}, indent=2))


if __name__ == "__main__":
    main()
