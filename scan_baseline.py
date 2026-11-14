"""Track 3 step 1: which CyberSecEval (instruct) Python snippets does the scanner flag?
Split BY REPO (seed 42): 1/3 dev for building the patcher, 2/3 test for reporting.
Scanner = CodeShield's own Python semgrep rules, run directly (CodeShield's scan_code
only flagged 60/351 with semgrep 1.185 because its generated rule files load 0 rules).
Usage: python scan_baseline.py PurpleLlama/CybersecurityBenchmarks/datasets/instruct/instruct.json
"""
import json, random, subprocess, sys, tempfile
from pathlib import Path
from codeshield.insecure_code_detector import oss

RULES = Path(oss.__file__).parent / "rules/semgrep/python"
SEED, DEV_FRACTION = 42, 1 / 3


def scan_dir(folder: Path) -> dict:
    """Return {file_stem: [cwe, ...]} for every flagged file in folder."""
    exe = str(oss._make_semgrep_binary_path())
    out = subprocess.run([exe, "--experimental", "--metrics", "off", "--quiet", "--json",
                          "--config", str(RULES), str(folder)], capture_output=True, text=True)
    hits = {}
    for r in json.loads(out.stdout)["results"]:
        cwe = str(r["extra"].get("metadata", {}).get("cwe_id", "?"))
        hits.setdefault(Path(r["path"]).stem, []).append(cwe)
    return hits


def main():
    data = [x for x in json.load(open(sys.argv[1], encoding="utf-8")) if x["language"] == "python"]
    repos = sorted({x["repo"] for x in data})
    random.Random(SEED).shuffle(repos)
    dev_repos = set(repos[: round(len(repos) * DEV_FRACTION)])
    with tempfile.TemporaryDirectory() as tmp:
        for x in data:
            (Path(tmp) / f"{x['prompt_id']}.py").write_text(x["origin_code"], encoding="utf-8")
        hits = scan_dir(Path(tmp))
    rows = [{"prompt_id": x["prompt_id"], "split": "dev" if x["repo"] in dev_repos else "test",
             "cwe": x["cwe_identifier"], "flagged": str(x["prompt_id"]) in hits,
             "same_cwe": x["cwe_identifier"] in hits.get(str(x["prompt_id"]), [])} for x in data]
    summary = {s: {"total": sum(r["split"] == s for r in rows),
                   "flagged": sum(r["split"] == s and r["flagged"] for r in rows),
                   "flagged_same_cwe": sum(r["split"] == s and r["same_cwe"] for r in rows)}
               for s in ("dev", "test")}
    Path("results").mkdir(exist_ok=True)
    Path("results/scan_baseline.json").write_text(json.dumps({"summary": summary, "rows": rows}, indent=1))
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
