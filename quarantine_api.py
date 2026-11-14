"""quarantine_api.py: el criterio de cuarentena y la evidencia, por HTTP.

En api.py bastan dos líneas:
    from quarantine_api import router as quarantine_router
    app.include_router(quarantine_router)

POST /quarantine
    entrada: {original_code, patched_code, findings, verify, model}
             findings = la lista que devuelve /scan
             verify   = el objeto que devuelve /verify
             model    = opcional, el que devuelve /patch
    salida:  {route, priority, criteria, evidence}

No cambia /scan, /patch ni /verify. Si falta el estado o no se reconoce,
el caso sale como cuarentena P1: ante la duda, lo ve una persona.
"""
from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel

from quarantine import evidence, triage

router = APIRouter()


class QuarantineIn(BaseModel):
    original_code: str
    patched_code: str = ""
    findings: list = []
    verify: dict = {}
    model: Optional[str] = None


@router.post("/quarantine")
def quarantine(body: QuarantineIn) -> dict:
    cwes = [f["cwe"] for f in body.findings if isinstance(f, dict) and f.get("cwe")]
    result = triage(str(body.verify.get("status", "")), body.verify.get("reasons") or [], cwes)
    result["evidence"] = evidence(body.original_code, body.patched_code or body.original_code,
                                  [f for f in body.findings if isinstance(f, dict)],
                                  body.verify, model=body.model)
    return result
