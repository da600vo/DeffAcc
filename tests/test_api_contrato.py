"""Prueba de humo del contrato de la API (ARQUITECTURA.md, sección 5).
Dice en segundos si api.py, verify.py y patch.py encajan. Se salta si api.py no está.
No llama al LLM. Los ejemplos son los de la tabla 3.2: no usan muestras del dataset.
Corre con: python -m pytest -q tests/test_api_contrato.py"""
import importlib.util
import sys
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
api = pytest.importorskip("api")

from fastapi.testclient import TestClient  # noqa: E402

client = TestClient(api.app, raise_server_exceptions=False)

ORIGINAL = 'import os\n\ndef ping(host):\n    os.system("ping -c 1 " + host)\n    return True\n'
TABLA_3_2 = {
    "fixed": ('import subprocess\n\ndef ping(host):\n'
              '    subprocess.run(["ping", "-c", "1", host], check=False)\n    return True\n'),
    "fake_fix": 'import os\n\ndef ping(host):\n    # os.system("ping -c 1 " + host)\n    return True\n',
    "still_insecure": 'import os\n\ndef ping(host):\n    os.system("ping -c 1 " + host.strip())\n    return True\n',
}


def test_health_reports_the_pinned_versions():
    body = client.get("/health").json()
    assert body["ok"] is True
    assert body.get("versions_match_pinned", True), body.get("versions")


def test_scan_returns_cwe_line_and_rule():
    r = client.post("/scan", json={"code": ORIGINAL, "language": "python"})
    assert r.status_code == 200
    body = r.json()
    assert body["flagged"] is True
    assert [(f["cwe"], f["line"]) for f in body["findings"]] == [("CWE-78", 4)]
    assert body["findings"][0]["rule"]


def test_verify_gives_the_states_of_table_3_2():
    """Si verify.py no está, la API responde con un estado fijo. Esta prueba falla
    entonces a propósito: un estado fijo "fixed" deja pasar cualquier parche."""
    for expected, patched in TABLA_3_2.items():
        r = client.post("/verify", json={"original_code": ORIGINAL, "patched_code": patched})
        assert r.status_code == 200, r.text[:200]
        body = r.json()
        assert body["status"] == expected, (expected, body)
        assert isinstance(body["reasons"], list) and isinstance(body["original_parses"], bool)


def test_patch_module_exposes_the_function_the_api_calls():
    """api.py hace `from patch import patch`. Si patch.py existe sin esa función, /patch da 500."""
    if importlib.util.find_spec("patch") is None:
        pytest.skip("patch.py todavía no está")
    import patch as patch_module
    assert callable(getattr(patch_module, "patch", None)), \
        "patch.py debe exponer patch(code, findings) -> {patched_code, model}"


def test_scan_rejects_other_languages_without_crashing():
    assert client.post("/scan", json={"code": "x", "language": "javascript"}).status_code in (400, 422)


def test_quarantine_is_mounted_when_available():
    routes = {getattr(r, "path", "") for r in api.app.routes}
    if "/quarantine" not in routes:
        pytest.skip("api.py no incluye quarantine_api.router: son dos líneas")
    r = client.post("/quarantine", json={"original_code": ORIGINAL, "patched_code": TABLA_3_2["fake_fix"],
                                         "findings": [{"cwe": "CWE-78", "line": 4, "rule": "x"}],
                                         "verify": {"status": "fake_fix", "reasons": ["flagged_line_commented:L4"],
                                                    "original_parses": True}})
    assert r.status_code == 200 and r.json()["priority"] == "P1"
