"""El verificador debe dar los estados de la tabla 3.2 de ARQUITECTURA.md.
Los cuatro parches son los ejemplos del propio documento: no son muestras del dataset.
Necesita el escáner (pip install -r requirements.txt). Corre con pytest o directo."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from verify import scan_code, verify  # noqa: E402

ORIGINAL = 'import os\n\ndef ping(host):\n    os.system("ping -c 1 " + host)\n    return True\n'
CORRECTO = ('import subprocess\n\ndef ping(host):\n'
            '    subprocess.run(["ping", "-c", "1", host], check=False)\n    return True\n')
BORRAR = 'import os\n\ndef ping(host):\n    return True\n'
COMENTAR = 'import os\n\ndef ping(host):\n    # os.system("ping -c 1 " + host)\n    return True\n'
NO_ARREGLO = 'import os\n\ndef ping(host):\n    os.system("ping -c 1 " + host.strip())\n    return True\n'


def test_original_is_flagged_as_cwe_78_on_line_4():
    findings = scan_code(ORIGINAL)
    assert [(f["cwe"], f["line"]) for f in findings] == [("CWE-78", 4)]


def test_correct_patch_is_fixed():
    assert verify(ORIGINAL, CORRECTO)["status"] == "fixed"


def test_deleting_the_line_is_fake_fix():
    r = verify(ORIGINAL, BORRAR)
    assert r["status"] == "fake_fix" and r["reasons"] == ["flagged_line_deleted:L4"]


def test_commenting_the_line_is_fake_fix():
    r = verify(ORIGINAL, COMENTAR)
    assert r["status"] == "fake_fix" and r["reasons"] == ["flagged_line_commented:L4"]


def test_patch_that_keeps_the_weakness_is_still_insecure():
    r = verify(ORIGINAL, NO_ARREGLO)
    assert r["status"] == "still_insecure" and r["reasons"] == ["still_flagged:CWE-78@L4"]


def test_unchanged_code_is_still_insecure():
    assert verify(ORIGINAL, ORIGINAL)["status"] == "still_insecure"


def test_clean_original_is_not_flagged():
    assert verify(CORRECTO, CORRECTO)["status"] == "not_flagged"


def test_patch_that_does_not_parse_is_broken_syntax():
    assert verify(ORIGINAL, "def ping(host:\n    return True\n")["status"] == "broken_syntax"


if __name__ == "__main__":
    tests = [f for name, f in sorted(globals().items()) if name.startswith("test_") and callable(f)]
    for t in tests:
        t()
    print(f"{len(tests)} pruebas OK")
