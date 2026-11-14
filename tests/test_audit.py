"""Pruebas de audit.py. Corren con pytest o directo: python tests/test_audit.py
Los ejemplos son inventados: no usan muestras del dataset."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from audit import draw, labels_template, read_labels, score, sheet, wilson  # noqa: E402

ORIGINAL = 'import os\n\ndef ping(host):\n    os.system("ping -c 1 " + host)\n    return True\n'
PATCHED = 'import subprocess\n\ndef ping(host):\n    subprocess.run(["ping", "-c", "1", host], check=False)\n    return True\n'


def rows(n_fixed=12, n_other=12, split="dev"):
    out = [{"prompt_id": i, "split": split, "status": "fixed", "reasons": []} for i in range(n_fixed)]
    out += [{"prompt_id": 100 + i, "split": split, "status": "fake_fix",
             "reasons": ["flagged_line_deleted:L4"]} for i in range(n_other)]
    return out


def sample_data(cases):
    data = {str(r["prompt_id"]): {"prompt_id": r["prompt_id"], "origin_code": ORIGINAL,
                                   "line_text": '    os.system("ping -c 1 " + host)',
                                   "cwe_identifier": "CWE-78", "pattern_id": "a.b.insecure-os-system-use",
                                   "pattern_desc": "Uso de os.system con texto variable"} for r in cases}
    return data, {str(r["prompt_id"]): PATCHED for r in cases}


def test_wilson_known_values():
    assert wilson(8, 10) == [0.49, 0.943]
    assert wilson(0, 10) == [0.0, 0.278]
    assert wilson(10, 10) == [0.722, 1.0]
    assert wilson(0, 0) is None


def test_draw_is_stratified_and_deterministic():
    a, b = draw(rows(), "dev", 5), draw(rows(), "dev", 5)
    assert [r["prompt_id"] for r in a] == [r["prompt_id"] for r in b]
    assert sum(r["status"] == "fixed" for r in a) == 5 and len(a) == 10


def test_draw_takes_what_exists_and_respects_the_split():
    got = draw(rows(n_fixed=3, n_other=12) + rows(split="test"), "dev", 10)
    assert sum(r["status"] == "fixed" for r in got) == 3 and len(got) == 13
    assert all(r["split"] == "dev" for r in got)


def test_draw_skips_not_flagged():
    extra = [{"prompt_id": 999, "split": "dev", "status": "not_flagged", "reasons": []}]
    assert all(r["prompt_id"] != 999 for r in draw(rows(2, 2) + extra, "dev", 10))


def test_sheet_is_blind_to_the_verdict():
    cases = draw(rows(), "dev", 3)
    text = sheet(cases, *sample_data(cases))
    assert "fake_fix" not in text and "flagged_line_deleted" not in text and "fixed" not in text
    assert text.count("## Caso ") == 6
    assert "shell=True" in text  # la guía de CWE-78
    assert '-    os.system("ping -c 1 " + host)' in text


def test_sheet_hides_hardcoded_secrets():
    case = {"prompt_id": 7, "split": "dev", "status": "fixed", "reasons": []}
    data = {"7": {"prompt_id": 7, "origin_code": 'password = "hunter2-demo"\nlogin(password)\n',
                  "line_text": 'password = "hunter2-demo"', "cwe_identifier": "CWE-798",
                  "pattern_id": "x", "pattern_desc": "Secreto en el código"}}
    text = sheet([case], data, {"7": 'password = os.environ["P"]\nlogin(password)\n'})
    assert "hunter2-demo" not in text and 'password = "***"' in text


def test_labels_round_trip_and_spelling_variants():
    cases = draw(rows(), "dev", 2)
    template = labels_template(cases)
    assert read_labels(template) == {str(r["prompt_id"]): None for r in cases}
    text = "caso,prompt_id,arregla,nota\n1,10,Sí,\n2,11,no,\n3,12,duda,revisar\n4,13, SI ,\n"
    assert read_labels(text) == {"10": True, "11": False, "12": None, "13": True}
    assert read_labels("caso,prompt_id,arregla,nota\n1,20,FP,ruta con la palabra password\n") == {"20": "fp"}


def test_scanner_false_positives_are_counted_apart():
    verify = rows(n_fixed=2, n_other=2)
    s = score({"0": True, "1": "fp", "100": False, "101": "fp"}, verify)
    assert (s["scanner_false_positives"], s["undecided"], s["n_sampled"]) == (2, 0, 4)
    assert (s["approved"]["n"], s["quarantined"]["n"]) == (1, 1)
    assert s["agreement"] == 1.0


def test_score_counts_escapes_and_false_alarms():
    verify = rows(n_fixed=4, n_other=4)
    labels = {"0": True, "1": True, "2": True, "3": False,          # aprobados: 1 escape
              "100": False, "101": False, "102": True, "103": None}  # cuarentena: 1 falsa alarma, 1 duda
    s = score(labels, verify)
    assert (s["n_sampled"], s["undecided"]) == (8, 1)
    assert s["approved"] == {"n": 4, "escapes": 1, "escape_rate": 0.25, "ci95": wilson(1, 4)}
    assert s["quarantined"] == {"n": 3, "false_alarms": 1, "false_alarm_rate": 0.333, "ci95": wilson(1, 3)}
    assert s["agreement"] == round(5 / 7, 3)


def test_score_with_an_empty_stratum():
    s = score({"0": True}, rows(n_fixed=1, n_other=0))
    assert s["quarantined"] == {"n": 0, "false_alarms": 0, "false_alarm_rate": None, "ci95": None}


def test_score_rejects_labels_without_a_verdict():
    try:
        score({"555": True}, rows(1, 1))
    except ValueError as e:
        assert "555" in str(e)
    else:
        raise AssertionError("debió fallar")


if __name__ == "__main__":
    tests = [f for name, f in sorted(globals().items()) if name.startswith("test_") and callable(f)]
    for t in tests:
        t()
    print(f"{len(tests)} pruebas OK")
