"""Track 3 step 1: which CyberSecEval (instruct) Python snippets does the scanner flag?
Scanner = Insecure Code Detector (ICD) of CodeShield, the same detector CyberSecEval uses
(regex + semgrep rules, usecase CYBERSECEVAL). Versions are pinned in requirements.txt:
results change with the semgrep version (with semgrep 1.185 its generated rules load 0 rules).
Split BY REPO (seed 42): 1/3 dev for building the patcher, 2/3 test for reporting.
Usage: python scan_baseline.py PurpleLlama/CybersecurityBenchmarks/datasets/instruct/instruct.json
"""
import asyncio, json, random, sys, tempfile
from importlib.metadata import version
from pathlib import Path
from codeshield.insecure_code_detector import insecure_code_detector as icd
from codeshield.insecure_code_detector.languages import Language

SEED, DEV_FRACTION = 42, 1 / 3
EXPECTED = {"codeshield": "1.0.1", "semgrep": "1.79.0"}


def scan_code(code: str) -> list:
    """Return the list of CWE ids ICD finds in one Python snippet (empty list = clean)."""
    issues = asyncio.run(icd.analyze(Language.PYTHON, code))
    return [str(i.cwe_id) for i in issues]


def scan_dir(folder: Path) -> dict:
    """Return {file_stem: [cwe, ...]} for every flagged .py file in folder."""
    hits = {}
    for f in sorted(Path(folder).glob("*.py")):
        cwes = scan_code(f.read_text(encoding="utf-8"))
        if cwes:
            hits[f.stem] = cwes
    return hits


def main():
    versions = {p: version(p) for p in EXPECTED}
    if versions != EXPECTED:
        print(f"AVISO: versiones {versions} distintas de las fijadas {EXPECTED}. "
              "Corre: pip install -r requirements.txt", file=sys.stderr)
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
    Path("results/scan_baseline.json").write_text(
        json.dumps({"versions": versions, "summary": summary, "rows": rows}, indent=1))
    print(json.dumps({"versions": versions, **summary}, indent=1))


if __name__ == "__main__":
    main()
