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

    # Headers del correo como dict de strings (opcional si se provee raw_email)
    headers: Optional[dict[str, str | list[str]]] = None
    raw_email: Optional[str] = None

    # Opcionales
    org_id: Optional[str] = None
    enrich: bool = False  # Consultar RDAP (lento, deshabilitado por default en API)

    model_config = {
        "json_schema_extra": {
            "example": {
                "raw_email": "Return-Path: <test@example.com>\nReceived: from mx.example.com...\nMessage-ID: <123>\n",
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
    - **raw_email**: String con los encabezados en bruto (RFC 822 format).
    - **org_id**: ID de organización para comparar con firma (opcional).
    - **enrich**: Si `true`, consulta RDAP para enriquecer ASNs (más lento).
    """
    from eti_core.traceroute.parser import parse_received_headers_from_text
    from eti_core.traceroute.ordering import detect_orphan_hops, sort_hops_by_timestamp
    from eti_core.auth.spf_dkim_dmarc import parse_all_auth_headers
    from eti_core.scoring.eti import calculate_eti
    from eti_core.msgid.extractor import extract_domain_from_msgid
    import re
    import logging
    from email.parser import Parser
    from email import policy as email_policy

    log = logging.getLogger("eti.api")

    try:
        headers = {}
        raw_text_for_hops = ""

        if request.raw_email:
            raw_text_for_hops = request.raw_email
            msg = Parser(policy=email_policy.default).parsestr(request.raw_email, headersonly=True)
            for k, v in msg.items():
                k_lower = k.lower()
                val_str = str(v)
                if k_lower in headers:
                    if isinstance(headers[k_lower], list):
                        headers[k_lower].append(val_str)
                    else:
                        headers[k_lower] = [headers[k_lower], val_str]
                else:
                    headers[k_lower] = val_str
        elif request.headers:
            headers = {k.lower(): v for k, v in request.headers.items()}
            # Reconstruct Received headers text for parsing
            received_list = headers.get("received", [])
            if isinstance(received_list, str):
                received_list = [received_list]
            raw_text_for_hops = "\n".join(f"Received: {r}" for r in received_list)
        else:
            raise HTTPException(status_code=422, detail="Se requiere 'headers' o 'raw_email'")

        # Parsear Received: directamente del raw completo (preserva IPs y formato original)
        if raw_text_for_hops:
            hops = parse_received_headers_from_text(raw_text_for_hops)
        else:
            hops = []

        hops = sort_hops_by_timestamp(hops)
        hops = detect_orphan_hops(hops)

        # Enriquecer con ASN/RDAP si se solicita (o usar prefijos conocidos como fallback)
        from eti_core.enrichment.asn_lookup import classify_asn
        from eti_core.models import HopClassification
        for hop in hops:
            if hop.classification == HopClassification.UNKNOWN:
                host_str = f"{hop.from_host or ''} {hop.by_host or ''}"
                cls, org = classify_asn(hop.asn, hop.ip, host=host_str)
                if cls != HopClassification.UNKNOWN:
                    hop.classification = cls
                    hop.asn_org = org

        if request.enrich and hops:
            from eti_core.enrichment.rdap_client import enrich_hops
            from eti_core.enrichment.cache import RDAPCache
            with RDAPCache() as cache:
                hops = enrich_hops(hops, cache=cache)

        auth = parse_all_auth_headers(headers)
        # DEBUG: ver qué llega y qué se parsea
        auth_raw = headers.get("authentication-results", None)
        log.warning(
            "ETI DEBUG | from=%s | auth-results-header=%s | parsed_spf=%s dkim=%s dmarc=%s raw_present=%s",
            headers.get("from", "?"),
            repr(str(auth_raw)[:200]) if auth_raw else "AUSENTE",
            auth.spf.value,
            auth.dkim.value,
            auth.dmarc.value,
            auth.raw is not None,
        )

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

        from eti_core.msgid.signature import OrgSignature
        from pathlib import Path

        org_sig = None
        sender_in_db = False       # Si el dominio emisor está en nuestra DB
        spoofing_detected = False  # Si se detectó suplantación de identidad
        if sender_domain:
            base_dir = Path(__file__).resolve().parent.parent.parent / "data" / "baselines"
            if not base_dir.exists():
                for cand in [
                    Path.cwd() / "data" / "baselines",
                    Path.cwd() / "core-framework" / "data" / "baselines",
                    Path("/home/luval/Escritorio/Email-Trust/core-framework/data/baselines"),
                ]:
                    if cand.exists():
                        base_dir = cand
                        break
            
            # Mapa completo de dominios conocidos → firma
            domain_to_sig = {
                # Google
                "gmail.com": "google",
                "google.com": "google",
                "googlemail.com": "google",
                # Microsoft
                "hotmail.com": "microsoft",
                "outlook.com": "microsoft",
                "live.com": "microsoft",
                "microsoft.com": "microsoft",
                # Banca chilena
                "bancoestado.cl": "bancoestado",
                "bestado.cl": "bancoestado",
                "acepta.com": "acepta",
                "bancochile.cl": "bancochile",
                "falabella.com": "falabella",
                "bancofalabella.cl": "bancofalabella",
                "cmrfalabella.com": "bancofalabella",
                "bci.cl": "bci",
                "tbci.cl": "bci",
                "santander.cl": "santander",
                "itau.cl": "itau",
                "scotiabank.cl": "bci",
                "provida.cl": "provida",
                "afphabitat.cl": "afphabitat",
                "unoafp.cl": "unoafp",
                "tenpo.cl": "tenpo",
                "servipag.cl": "servipag",
                # Retail / E-commerce
                "ripley.cl": "ripley",
                "paris.cl": "paris",
                "hites.com": "hites",
                "abcdin.cl": "abcdin",
                "mercadolibre.cl": "mercadolibre",
                "mercadolibre.com": "mercadolibre",
                "dafiti.cl": "dafiti",
                # Servicios
                "entel.cl": "google",  # usa Google Workspace
                "movistar.cl": "movistar",
                "wom.cl": "wom",
                "spotify.com": "spotify",
                "netflix.com": "netflix",
                "uber.com": "uber",
                "pedidosya.com": "pedidosya",
                "paypal.com": "paypal",
                "linkedin.com": "linkedin",
            }

            # Detectar si el From display name menciona una entidad conocida
            # pero el dominio real del correo no pertenece a esa entidad → SPOOFING
            spoofing_detected = False
            from_display = re.search(r'^"?([^"<]+)"?\s*<', from_header)
            display_name = from_display.group(1).strip().lower() if from_display else ""

            # Lista de nombres de marcas conocidas que pueden ser suplantadas
            known_brand_names = [
                "banco estado", "bancoestado", "banco de chile", "bancochile",
                "bci", "santander", "falabella", "cmr", "ripley", "paris",
                "mercado libre", "mercadolibre", "itaú", "itau", "scotiabank",
                "sii", "servicio de impuestos", "tenpo", "servipag", "afp habitat",
                "provida", "paypal", "netflix", "spotify", "amazon", "microsoft",
                "google", "apple", "uber", "pedidosya", "linkedin",
            ]

            org_name = None
            sender_domain_lower = sender_domain.lower() if sender_domain else ""

            # Verificar si el dominio real está en nuestro mapa
            sender_in_db = False
            for d, sig in domain_to_sig.items():
                if d in sender_domain_lower or sender_domain_lower.endswith("." + d):
                    org_name = sig
                    sender_in_db = True
                    break

            # Buscar también por prefijo en los archivos de firma
            if not org_name and base_dir.exists():
                for pf in base_dir.glob("*_signature.json"):
                    org_prefix = pf.name.replace("_signature.json", "")
                    if org_prefix in sender_domain_lower:
                        org_name = org_prefix
                        sender_in_db = True
                        break

            # Detectar spoofing: display name menciona una marca conocida
            # pero el dominio real NO pertenece a esa entidad
            if not sender_in_db and display_name:
                for brand in known_brand_names:
                    if brand in display_name:
                        spoofing_detected = True
                        break

            if org_name and base_dir.exists():
                sig_file = base_dir / f"{org_name}_signature.json"
                if sig_file.exists():
                    try:
                        org_sig = OrgSignature.load(sig_file)
                    except Exception:
                        pass

        result = calculate_eti(
            email_headers,
            org_signature=org_sig,
            sender_in_db=sender_in_db if sender_domain else False,
            spoofing_detected=spoofing_detected,
        )
        return result

    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Error procesando headers: {str(e)}")
