"""Pruebas de POST /quarantine. Necesitan fastapi y httpx; si faltan, se saltan.
Los ejemplos son los de la tabla 3.2 de ARQUITECTURA.md: no usan muestras del dataset."""
import sys
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from quarantine_api import router  # noqa: E402

app = FastAPI()
app.include_router(router)
client = TestClient(app)

ORIGINAL = 'import os\n\ndef ping(host):\n    os.system("ping -c 1 " + host)\n    return True\n'
CORRECTO = ('import subprocess\n\ndef ping(host):\n'
            '    subprocess.run(["ping", "-c", "1", host], check=False)\n    return True\n')
BORRAR = 'import os\n\ndef ping(host):\n    return True\n'
FINDINGS = [{"cwe": "CWE-78", "line": 4, "rule": "insecure-os-system-use"}]


def post(patched, verify, **extra):
    r = client.post("/quarantine", json={"original_code": ORIGINAL, "patched_code": patched,
                                         "findings": FINDINGS, "verify": verify, **extra})
    assert r.status_code == 200
    return r.json()


def test_fake_fix_goes_to_quarantine_p1_with_evidence():
    j = post(BORRAR, {"status": "fake_fix", "reasons": ["flagged_line_deleted:L4"], "original_parses": True},
             model="gemini-x")
    assert (j["route"], j["priority"]) == ("cuarentena", "P1")
    assert j["criteria"] == ["fake_fix", "critical_unresolved:CWE-78"]
    assert (j["status"], j["reasons"], j["original_parses"]) == ("fake_fix", ["flagged_line_deleted:L4"], True)
    assert j["evidence"]["findings"][0]["line_text"] == 'os.system("ping -c 1 " + host)'
    assert j["evidence"]["provenance"]["patch_model"] == "gemini-x"
    assert any(l.startswith("-") and "os.system" in l for l in j["evidence"]["diff"])


def test_fixed_goes_out_as_proposed_patch_with_evidence():
    j = post(CORRECTO, {"status": "fixed", "reasons": [], "original_parses": True})
    assert (j["route"], j["priority"], j["criteria"]) == ("parche_propuesto", "P3", [])
    assert j["evidence"]["verify"]["status"] == "fixed"


def test_missing_or_unknown_status_fails_closed():
    assert post(CORRECTO, {})["priority"] == "P1"
    j = post(CORRECTO, {"status": "desconocido", "reasons": []})
    assert (j["route"], j["priority"]) == ("cuarentena", "P1")
    assert j["criteria"][0] == "unknown_status:desconocido"
    assert post(CORRECTO, {})["status"] is None


def test_bad_request_is_rejected():
    assert client.post("/quarantine", json={"patched_code": "x"}).status_code == 422
