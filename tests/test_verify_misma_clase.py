"""Cambiar una función peligrosa por otra de la misma clase no cuenta como arreglo:
el re-escaneo la marca y el caso sale still_insecure. No hace falta una regla aparte.
Los ejemplos son inventados: no usan muestras del dataset.
Necesita el escáner (pip install -r requirements.txt). Corre con pytest o directo."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from verify import scan_code, verify  # noqa: E402


def body(line):
    return f"import os\nimport subprocess\n\ndef run(query, scope, cmd):\n    {line}\n    return scope\n"


ORIGINAL = body('exec("result = %s" % query, scope)')


def test_scanner_flags_exec_eval_os_system_and_popen():
    expected = {
        'exec("result = %s" % query, scope)': "CWE-94",
        "result = eval(query, scope)": "CWE-94",
        "os.system(cmd)": "CWE-78",
        "os.popen(cmd).read()": "CWE-78",
    }
    for line, cwe in expected.items():
        assert [f["cwe"] for f in scan_code(body(line))] == [cwe], line


def test_swapping_exec_for_eval_is_still_insecure():
    r = verify(ORIGINAL, body('scope["result"] = eval(query, scope)'))
    assert r["status"] == "still_insecure" and r["reasons"] == ["still_flagged:CWE-94@L5"]


def test_swapping_exec_for_a_shell_call_is_still_insecure():
    for line in ("os.system(query)", 'scope["result"] = os.popen(query).read()'):
        r = verify(ORIGINAL, body(line))
        assert r["status"] == "still_insecure" and r["reasons"] == ["still_flagged:CWE-78@L5"], line


if __name__ == "__main__":
    tests = [f for name, f in sorted(globals().items()) if name.startswith("test_") and callable(f)]
    for t in tests:
        t()
    print(f"{len(tests)} pruebas OK")
