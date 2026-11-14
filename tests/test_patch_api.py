"""patch.patch(code, findings): lo que llama la API en POST /patch.
No llama a Gemini: la respuesta del modelo se reemplaza por una fija.
Los ejemplos son los de la tabla 3.2: no usan muestras del dataset."""
import sys
from pathlib import Path

import pytest

pytest.importorskip("google.genai")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import patch as patch_module  # noqa: E402

ORIGINAL = 'import os\n\ndef ping(host):\n    os.system("ping -c 1 " + host)\n    return True\n'
FIXED = ('import subprocess\n\ndef ping(host):\n'
         '    subprocess.run(["ping", "-c", "1", host], check=False)\n    return True\n')
FINDINGS = [{"cwe": "CWE-78", "line": 4, "rule": "insecure-os-system-use"}]


@pytest.fixture
def fake_gemini(monkeypatch):
    seen = {}

    def fake_call(client, prompt, retries=5):
        seen["prompt"] = prompt
        return seen.get("answer", FIXED)

    monkeypatch.setattr(patch_module, "call_gemini", fake_call)
    monkeypatch.setattr(patch_module, "_client", object())  # evita crear el cliente real
    return seen


def test_patch_returns_the_contract_shape(fake_gemini):
    out = patch_module.patch(ORIGINAL, FINDINGS)
    assert out == {"patched_code": FIXED, "model": "gemini-3.5-flash-lite"}


def test_prompt_carries_the_cwe_the_flagged_line_and_the_code(fake_gemini):
    patch_module.patch(ORIGINAL, FINDINGS)
    prompt = fake_gemini["prompt"]
    assert "CWE-78" in prompt and "insecure-os-system-use" in prompt
    assert 'os.system("ping -c 1 " + host)' in prompt and "def ping(host):" in prompt


def test_markdown_fences_are_removed(fake_gemini):
    fake_gemini["answer"] = "```python\n" + FIXED + "```"
    assert patch_module.patch(ORIGINAL, FINDINGS)["patched_code"] == FIXED


def test_empty_answer_falls_back_to_the_original_code(fake_gemini):
    fake_gemini["answer"] = ""
    assert patch_module.patch(ORIGINAL, FINDINGS)["patched_code"] == ORIGINAL


def test_works_without_findings_or_with_a_line_out_of_range(fake_gemini):
    assert patch_module.patch(ORIGINAL, [])["model"] == "gemini-3.5-flash-lite"
    assert patch_module.patch(ORIGINAL, [{"cwe": "CWE-78", "line": 99, "rule": "x"}])["patched_code"] == FIXED


def test_missing_key_gives_a_clear_error(monkeypatch):
    monkeypatch.setattr(patch_module, "_client", None)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.chdir(Path(__file__).parent)  # carpeta sin .env
    with pytest.raises(RuntimeError, match="GEMINI_API_KEY"):
        patch_module.patch(ORIGINAL, FINDINGS)


def test_api_patch_endpoint_uses_it_and_the_flow_reaches_fixed(fake_gemini):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    api = pytest.importorskip("api")
    from fastapi.testclient import TestClient
    client = TestClient(api.app, raise_server_exceptions=False)
    r = client.post("/patch", json={"code": ORIGINAL, "findings": FINDINGS})
    assert r.status_code == 200, r.text[:200]
    assert r.json() == {"patched_code": FIXED, "model": "gemini-3.5-flash-lite"}
    v = client.post("/verify", json={"original_code": ORIGINAL, "patched_code": r.json()["patched_code"]})
    assert v.json()["status"] == "fixed"
