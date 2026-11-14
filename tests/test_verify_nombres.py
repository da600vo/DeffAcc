"""Regla 4d de verify.py: nombres nuevos que nadie define.
Los ejemplos son inventados o salen de la tabla 3.2 de ARQUITECTURA.md: no usan muestras
del dataset. Necesita el escáner (pip install -r requirements.txt). Corre con pytest o directo."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import verify as verify_module  # noqa: E402
from verify import new_undefined_names, verify  # noqa: E402

PING = 'import os\n\ndef ping(host):\n    os.system("ping -c 1 " + host)\n    return True\n'


def test_invented_helper_is_reported_even_in_a_fragment_that_does_not_parse():
    original = ("        cursor = conn.cursor()\n"
                "    cursor.execute('SELECT %s()' % func)\n"
                "    return cursor.fetchall(\n")
    patched = original.replace("% func)", "% sanitize_identifier(func))")
    assert new_undefined_names(original, patched) == ["sanitize_identifier"]


def test_module_used_without_import_is_reported_when_the_fragment_shows_its_imports():
    original = 'import os\n\ndef disk_usage(path):\n    return os.popen("du -sh " + path).read()\n'
    patched = ('import os\n\ndef disk_usage(path):\n'
               '    return subprocess.check_output(["du", "-sh", path]).decode()\n')
    assert new_undefined_names(original, patched) == ["subprocess"]
    assert new_undefined_names(original, patched.replace("import os\n", "import os\nimport subprocess\n")) == []


def test_module_without_import_is_reported_even_when_no_imports_are_visible():
    original = '    password = "hunter2-demo"\n    return connect(user, password)\n'
    patched = '    password = os.environ["DB_PASSWORD"]\n    return connect(user, password)\n'
    assert new_undefined_names(original, patched) == ["os"]
    assert new_undefined_names(original, "    import os\n" + patched) == []


def test_module_style_names_can_get_the_benefit_of_the_doubt():
    original = '    password = "hunter2-demo"\n    return connect(user, password)\n'
    patched = '    password = os.environ["DB_PASSWORD"]\n    return connect(user, lookup(password))\n'
    verify_module.REPORT_MODULE_STYLE_NAMES = False
    try:
        assert new_undefined_names(original, patched) == ["lookup"]  # la función inventada sigue saliendo
    finally:
        verify_module.REPORT_MODULE_STYLE_NAMES = True
    assert new_undefined_names(original, patched) == ["lookup", "os"]


def test_python_2_builtins_are_not_reported():
    assert new_undefined_names("value = str(x)\n", "value = unicode(x)\nfor i in xrange(3): pass\n") == []


def test_keyword_arguments_are_not_names():
    original = 'import subprocess\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)\n'
    patched = ('import subprocess\nimport shlex\n\ndef run(cmd):\n'
               '    return subprocess.run(shlex.split(cmd), shell=False, check=False, timeout=30)\n')
    assert new_undefined_names(original, patched) == []


def test_names_the_patch_defines_are_fine():
    original = 'def f(items, path):\n    data = open(path).read()\n    return eval(data)\n'
    patched = ('import json\n\n'
               'def f(items, path):\n'
               '    with open(path) as handle:\n'
               '        text = handle.read()\n'
               '    first, rest = text[:1], text[1:]\n'
               '    for index, (key, value) in enumerate(items):\n'
               '        pass\n'
               '    try:\n'
               '        parsed = json.loads(text)\n'
               '    except ValueError as err:\n'
               '        parsed = None\n'
               '    pick = lambda row, default=None: row or default\n'
               '    total = [cell for cell in items if (size := len(cell)) > 1]\n'
               '    return pick(parsed), first, rest, index, key, value, err, total, size\n')
    assert new_undefined_names(original, patched) == []


def test_helper_defined_in_the_patch_is_fine():
    original = 'def lookup(cursor, name):\n    cursor.execute("SELECT * FROM t WHERE n = \'%s\'" % name)\n'
    patched = ('def _clean(value, *extra, **options):\n    return str(value)\n\n'
               'def lookup(cursor, name):\n'
               '    cursor.execute("SELECT * FROM t WHERE n = %s", (_clean(name),))\n')
    assert new_undefined_names(original, patched) == []


def test_imported_names_are_fine_and_star_imports_disable_the_rule():
    original = 'print("a")\n'
    assert new_undefined_names(original, 'from shlex import quote\nprint(quote("a"))\n') == []
    multi = 'from os.path import (\n    join,\n    basename as base,\n)\nprint(join("a", base("b")))\n'
    assert new_undefined_names(original, multi) == []
    assert new_undefined_names(original, 'from helpers import *\nprint(mystery("a"))\n') == []
    assert new_undefined_names(original, 'print(mystery("a"))\n') == ["mystery"]


def test_names_already_in_the_original_are_known():
    assert new_undefined_names("value = helper(x)\n", "value = helper(x.strip())\n") == []


def test_strings_and_comments_do_not_count():
    original = "value = compute(x)\n"
    patched = '# usar sanitize(x) aquí\nnote = "call foo() later"\nvalue = compute(x)\n'
    assert new_undefined_names(original, patched) == []


def test_identical_and_shorter_patches_report_nothing():
    assert new_undefined_names(PING, PING) == []
    assert new_undefined_names(PING, 'import os\n\ndef ping(host):\n    return True\n') == []


def test_patch_the_tokenizer_cannot_read_is_skipped():
    assert new_undefined_names("x = 1\n", "x = 'abc\nmystery(x)\n") == []


def test_original_the_tokenizer_cannot_read_widens_what_is_known():
    assert new_undefined_names("y = 'abc\nresult = helper(y)\n", "y = 'abc'\nresult = helper(y)\n") == []


def test_verify_marks_an_invented_helper_as_fake_fix():
    r = verify(PING, 'import os\n\ndef ping(host):\n    safe_ping(host)\n    return True\n')
    assert r["status"] == "fake_fix" and r["reasons"] == ["undefined_name:safe_ping"]


def test_verify_marks_a_module_without_import_as_fake_fix():
    patched = ('import os\n\ndef ping(host):\n'
               '    subprocess.run(["ping", "-c", "1", host], check=False)\n    return True\n')
    r = verify(PING, patched)
    assert r["status"] == "fake_fix" and r["reasons"] == ["undefined_name:subprocess"]
    assert verify(PING, patched.replace("import os\n", "import subprocess\n"))["status"] == "fixed"


if __name__ == "__main__":
    tests = [f for name, f in sorted(globals().items()) if name.startswith("test_") and callable(f)]
    for t in tests:
        t()
    print(f"{len(tests)} pruebas OK")
