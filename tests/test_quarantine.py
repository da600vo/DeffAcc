"""Pruebas de quarantine.py. Corren con pytest o directo: python tests/test_quarantine.py
Los ejemplos son inventados: no usan muestras del dataset."""
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from quarantine import MAX_DIFF_LINES, evidence, queue_key, respond, summarize, triage  # noqa: E402

ORIGINAL = "import random\n\ndef new_token():\n    token = random.randint(0, 999999)\n    return token\n"
FIXED = "import secrets\n\ndef new_token():\n    token = secrets.randbelow(1000000)\n    return token\n"
VERIFY_OK = {"status": "fixed", "reasons": [], "original_parses": True}


def test_fixed_goes_out_as_proposed_patch():
    assert triage("fixed", [], ["CWE-78"]) == {"route": "parche_propuesto", "priority": "P3", "criteria": []}


def test_not_flagged_is_approved():
    assert triage("not_flagged", ["original_not_flagged"], [])["route"] == "aprobado"


def test_fake_fix_is_always_p1():
    t = triage("fake_fix", ["flagged_line_deleted:L4"], ["CWE-328"])
    assert (t["route"], t["priority"]) == ("cuarentena", "P1")
    assert t["criteria"] == ["fake_fix"]


def test_still_insecure_outside_top25_is_p2():
    t = triage("still_insecure", ["still_flagged:CWE-328@L4"], ["CWE-328"])
    assert (t["route"], t["priority"], t["criteria"]) == ("cuarentena", "P2", [])


def test_still_insecure_top25_is_p1():
    t = triage("still_insecure", ["still_flagged:CWE-78@L15"], ["CWE-78"])
    assert t["priority"] == "P1" and t["criteria"] == ["critical_unresolved:CWE-78"]


def test_patch_that_adds_a_new_cwe_is_p1():
    t = triage("still_insecure", ["still_flagged:CWE-94@L9"], ["CWE-328"])
    assert t["priority"] == "P1"
    assert t["criteria"] == ["new_cwe:CWE-94", "critical_unresolved:CWE-94"]


def test_new_cwe_needs_the_original_cwes():
    t = triage("still_insecure", ["still_flagged:CWE-328@L9"], [])
    assert t["criteria"] == [] and t["priority"] == "P2"


def test_broken_syntax_keeps_the_original_weakness_open():
    assert triage("broken_syntax", ["patch_does_not_parse"], ["CWE-502"])["priority"] == "P1"
    assert triage("broken_syntax", ["patch_does_not_parse"], ["CWE-798"])["priority"] == "P2"


def test_still_insecure_without_parsable_reasons_falls_back_to_original():
    assert triage("still_insecure", ["formato_nuevo"], ["CWE-89"])["criteria"] == ["critical_unresolved:CWE-89"]


def test_unknown_status_fails_closed():
    t = triage("error", [], ["CWE-328"])
    assert (t["route"], t["priority"]) == ("cuarentena", "P1")
    assert t["criteria"] == ["unknown_status:error"]


def test_evidence_has_provenance_diff_and_empty_human_decision():
    ev = evidence(ORIGINAL, FIXED, [{"cwe": "CWE-338", "line": 4, "rule": "r"}], VERIFY_OK,
                  model="m1", origin={"repo": "x/y", "file_path": "a.py"})
    prov = ev["provenance"]
    assert prov["sha256_original"] == hashlib.sha256(ORIGINAL.encode("utf-8")).hexdigest()
    assert prov["sha256_patch"] == hashlib.sha256(FIXED.encode("utf-8")).hexdigest()
    assert prov["patch_model"] == "m1" and prov["origin"]["repo"] == "x/y"
    assert set(prov["scanner"]) == {"codeshield", "semgrep"}
    assert ev["findings"][0]["line_text"] == "token = random.randint(0, 999999)"
    assert any(l.startswith("-") and "random.randint" in l for l in ev["diff"])
    assert any(l.startswith("+") and "secrets.randbelow" in l for l in ev["diff"])
    assert ev["verify"] == VERIFY_OK
    assert ev["decision"] == {"by": None, "at": None, "action": None, "note": None}


def test_evidence_never_leaks_a_hardcoded_secret():
    original = 'import db\n\ndef connect():\n    password = "hunter2-demo"\n    return db.open("svc", password)\n'
    patched = 'import db, os\n\ndef connect():\n    password = os.environ["DB_PASSWORD"]\n    return db.open("svc", password)\n'
    ev = evidence(original, patched, [{"cwe": "CWE-798", "line": 4, "rule": "insecure-hardcoded-secrets"}],
                  {"status": "still_insecure", "reasons": [], "original_parses": True})
    assert "hunter2-demo" not in json.dumps(ev)
    assert ev["findings"][0]["line_text"] == 'password = "***"'
    assert ev["redacted_secrets"] == 1


def test_non_secret_findings_are_not_redacted():
    original = 'import os\nos.system("ls " + folder)\n'
    ev = evidence(original, original, [{"cwe": "CWE-78", "line": 2, "rule": "r"}], VERIFY_OK)
    assert ev["findings"][0]["line_text"] == 'os.system("ls " + folder)'
    assert ev["redacted_secrets"] == 0


def test_long_diff_is_truncated_and_flagged():
    a = "\n".join(f"x{i} = {i}" for i in range(200))
    b = "\n".join(f"y{i} = {i}" for i in range(200))
    ev = evidence(a, b, [], VERIFY_OK)
    assert ev["diff_truncated"] is True and len(ev["diff"]) == MAX_DIFF_LINES


def test_respond_passes_verify_through_and_adds_triage_and_evidence():
    body = {"original_code": ORIGINAL, "patched_code": FIXED,
            "findings": [{"cwe": "CWE-78", "line": 4, "rule": "r"}, "basura"],
            "verify": {"status": "still_insecure", "reasons": ["el escáner sigue marcando el parche"],
                       "original_parses": True}, "model": "mock"}
    out = respond(body)
    assert (out["status"], out["original_parses"]) == ("still_insecure", True)
    assert (out["route"], out["priority"]) == ("cuarentena", "P1")
    assert out["criteria"] == ["critical_unresolved:CWE-78"]  # razones en prosa: se asume lo original abierto
    assert out["evidence"]["provenance"]["patch_model"] == "mock"
    assert len(out["evidence"]["findings"]) == 1


def test_respond_with_an_empty_body_fails_closed():
    out = respond({})
    assert (out["route"], out["priority"], out["status"]) == ("cuarentena", "P1", None)


def test_queue_order_is_priority_then_top25_rank():
    rows = [
        {"prompt_id": 1, "priority": "P3", "cwes": ["CWE-78"]},
        {"prompt_id": 2, "priority": "P2", "cwes": ["CWE-328"]},
        {"prompt_id": 3, "priority": "P1", "cwes": ["CWE-502"]},
        {"prompt_id": 4, "priority": "P1", "cwes": ["CWE-89"]},
    ]
    assert [r["prompt_id"] for r in sorted(rows, key=queue_key)] == [4, 3, 2, 1]


def test_summary_counts_the_specialist_load():
    rows = [
        {"split": "dev", "route": "cuarentena", "priority": "P1", "criteria": ["fake_fix"]},
        {"split": "dev", "route": "cuarentena", "priority": "P2", "criteria": []},
        {"split": "dev", "route": "parche_propuesto", "priority": "P3", "criteria": []},
        {"split": "dev", "route": "parche_propuesto", "priority": "P3", "criteria": []},
    ]
    s = summarize(rows)
    assert "test" not in s
    assert (s["dev"]["n_flagged"], s["dev"]["quarantine"], s["dev"]["P1"], s["dev"]["P2"], s["dev"]["P3"]) == (4, 2, 1, 1, 2)
    assert (s["dev"]["quarantine_rate"], s["dev"]["P1_rate"]) == (0.5, 0.25)
    assert s["dev"]["criteria"] == {"fake_fix": 1}


if __name__ == "__main__":
    tests = [f for name, f in sorted(globals().items()) if name.startswith("test_") and callable(f)]
    for t in tests:
        t()
    print(f"{len(tests)} pruebas OK")
