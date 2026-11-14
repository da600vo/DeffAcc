"""Regla 4e de verify.py: bloques del original que el parche repite.
Los ejemplos son inventados: no usan muestras del dataset.
Necesita el escáner (pip install -r requirements.txt). Corre con pytest o directo."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from verify import duplicated_blocks, verify  # noqa: E402

BLOCK = ['report = []', 'report.append("host: " + host)', 'report.append("status: ok")',
         'report.append("checked: yes")', 'report.append("source: demo")', 'report.append("version: 1")']
SCRIPT = "\n".join(["import os", "host = get_host()"] + BLOCK + ['os.system("ping -c 1 " + host)', "print(report)"]) + "\n"
FIX = 'subprocess.run(["ping", "-c", "1", host], check=False)'


def test_repeated_block_of_the_original_is_reported_with_its_lines():
    patched = "\n".join(["import os", "host = get_host()"] + BLOCK + BLOCK
                        + ['os.system("ping -c 1 " + host)', "print(report)"]) + "\n"
    assert duplicated_blocks(SCRIPT, patched) == ["L9-L14"]


def test_identical_code_and_a_one_line_fix_report_nothing():
    assert duplicated_blocks(SCRIPT, SCRIPT) == []
    assert duplicated_blocks(SCRIPT, SCRIPT.replace('os.system("ping -c 1 " + host)', FIX)) == []


def test_a_repeat_shorter_than_five_lines_is_not_a_block():
    short = ["import os", "host = get_host()"] + BLOCK[:4] + BLOCK[:4] + BLOCK[4:] + ["print(report)"]
    assert duplicated_blocks(SCRIPT, "\n".join(short) + "\n") == []


def test_only_counts_more_copies_than_the_original_had():
    twice = "\n".join(BLOCK + ["x = 1"] + BLOCK) + "\n"
    thrice = "\n".join(BLOCK + ["x = 1"] + BLOCK + ["y = 2"] + BLOCK) + "\n"
    assert duplicated_blocks(twice, twice) == []
    assert duplicated_blocks(twice, thrice) == ["L15-L20"]


def test_new_code_repeated_in_two_places_is_not_reported():
    new = ['result = subprocess.run(', '    ["git", "status"],', '    capture_output=True,',
           '    text=True,', '    check=False,', ')']
    patched = "\n".join(["import subprocess"] + new + ["print(result)"] + new) + "\n"
    assert duplicated_blocks("import os\nos.system('git status')\nos.system('git status')\n", patched) == []


def test_whole_file_returned_twice_is_one_block():
    assert duplicated_blocks(SCRIPT, SCRIPT + SCRIPT) == ["L11-L20"]


def test_indentation_and_blank_lines_are_ignored():
    patched = "\n".join(["import os", "host = get_host()"] + BLOCK + [""] + ["    " + l for l in BLOCK]
                        + ['os.system("ping -c 1 " + host)', "print(report)"]) + "\n"
    assert duplicated_blocks(SCRIPT, patched) == ["L10-L15"]


def test_trivial_repeats_are_not_blocks():
    original = "data = [\n" + "    1,\n" * 6 + "]\n"
    patched = "data = [\n" + "    1,\n" * 14 + "]\n"
    assert duplicated_blocks(original, patched) == []


def test_verify_marks_a_patch_that_repeats_a_block_as_fake_fix():
    original = SCRIPT.replace("import os\n", "import os\nimport subprocess\n")
    lines = original.splitlines()
    i = lines.index(BLOCK[0])
    patched = "\n".join(lines[:i] + BLOCK + lines[i:]).replace('os.system("ping -c 1 " + host)', FIX) + "\n"
    r = verify(original, patched)
    assert r["status"] == "fake_fix" and r["reasons"] == ["duplicated_block:L10-L15"]
    assert verify(original, original.replace('os.system("ping -c 1 " + host)', FIX))["status"] == "fixed"


if __name__ == "__main__":
    tests = [f for name, f in sorted(globals().items()) if name.startswith("test_") and callable(f)]
    for t in tests:
        t()
    print(f"{len(tests)} pruebas OK")
