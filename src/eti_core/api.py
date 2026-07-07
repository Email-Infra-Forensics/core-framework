"""
api.py — FastAPI mínimo para el framework ETI.

Un solo endpoint: POST /analyze
Recibe headers JSON y devuelve TrustScore.

Iniciar con:
  uvicorn eti_core.api:app --host 0.0.0.0 --port 8000

O con uv:
  uv run uvicorn eti_core.api:app --reload
"""

from __future__ import annotations

from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from eti_core import __version__
from eti_core.models import AuthResult, EmailHeaders, TrustScore

app = FastAPI(
    title="ETI Core API",
    description="Email Trust Index — API de análisis forense de correo",
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS abierto para desarrollo local (thunderbird-validator y web)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Esquemas de request/response
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    """Payload del endpoint /analyze."""

    # Headers del correo como dict de strings
    headers: dict[str, str | list[str]]

    # Opcionales
    org_id: Optional[str] = None
    enrich: bool = False  # Consultar RDAP (lento, deshabilitado por default en API)

    model_config = {
        "json_schema_extra": {
            "example": {
                "headers": {
                    "message-id": "<abc123@example.com>",
                    "from": "user@example.com",
                    "to": "dest@example.com",
                    "received": [
                        "from mail.example.com by mx.google.com with ESMTP; Mon, 1 Jan 2024 12:00:00 +0000",
                    ],
                    "authentication-results": "mx.google.com; dkim=pass; spf=pass; dmarc=pass",
                },
                "enrich": False,
            }
        }
    }


class HealthResponse(BaseModel):
    status: str
    version: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/", response_model=HealthResponse, tags=["meta"])
async def health():
    """Health check del servicio."""
    return HealthResponse(status="ok", version=__version__)


@app.post("/analyze", response_model=TrustScore, tags=["analysis"])
async def analyze(request: AnalyzeRequest) -> TrustScore:
    """
    Analiza los headers de un correo y devuelve el Email Trust Index.

    - **headers**: Dict de headers del correo (keys en lowercase).
    - **org_id**: ID de organización para comparar con firma (opcional).
    - **enrich**: Si `true`, consulta RDAP para enriquecer ASNs (más lento).
    """
    from eti_core.traceroute.parser import parse_received_headers_from_text
    from eti_core.traceroute.ordering import detect_orphan_hops, sort_hops_by_timestamp
    from eti_core.auth.spf_dkim_dmarc import parse_all_auth_headers
    from eti_core.scoring.eti import calculate_eti
    from eti_core.msgid.extractor import extract_domain_from_msgid
    import re

    try:
        headers = {k.lower(): v for k, v in request.headers.items()}

        # Parsear Received headers
        received = headers.get("received", [])
        if isinstance(received, str):
            received = [received]

        # Construir texto de headers para el parser
        headers_text = "\n".join(f"Received: {r}" for r in received)
        if headers_text:
            from email.parser import Parser
            from email import policy as email_policy
            msg = Parser(policy=email_policy.default).parsestr(headers_text, headersonly=True)
            hops = []
            received_raw = msg.get_all("Received") or []
            from eti_core.traceroute.parser import parse_received_header
            hops = [parse_received_header(raw, i) for i, raw in enumerate(received_raw)]
            hops = list(reversed(hops))
            for i, hop in enumerate(hops):
                hop.index = i
        else:
            hops = []

        hops = sort_hops_by_timestamp(hops)
        hops = detect_orphan_hops(hops)

        if request.enrich and hops:
            from eti_core.enrichment.rdap_client import enrich_hops
            from eti_core.enrichment.cache import RDAPCache
            with RDAPCache() as cache:
                hops = enrich_hops(hops, cache=cache)

        auth = parse_all_auth_headers(headers)

        message_id = headers.get("message-id", "")
        if isinstance(message_id, list):
            message_id = message_id[0]

        from_header = headers.get("from", "unknown")
        if isinstance(from_header, list):
            from_header = from_header[0]
        domain_match = re.search(r"@([\w.\-]+)", from_header)
        sender_domain = domain_match.group(1) if domain_match else extract_domain_from_msgid(message_id)

        email_headers = EmailHeaders(
            message_id=message_id or None,
            from_address=from_header,
            to_address=headers.get("to", "unknown") if isinstance(headers.get("to"), str) else "unknown",
            hops=hops,
            auth=auth,
            sender_domain=sender_domain,
        )

        return calculate_eti(email_headers, org_signature=None)

    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Error procesando headers: {str(e)}")
