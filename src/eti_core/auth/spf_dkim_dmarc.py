"""
auth/spf_dkim_dmarc.py — Parser del header Authentication-Results.

En lugar de re-validar criptográficamente SPF/DKIM (que requiere
acceso DNS en tiempo real), parseamos el header Authentication-Results
que ya fue calculado por el MTA receptor.

Formato RFC 7601:
  Authentication-Results: mx.google.com;
    dkim=pass header.i=@example.com header.s=selector;
    spf=pass (google.com: domain of user@example.com designates 1.2.3.4 as permitted sender)
      smtp.mailfrom=user@example.com;
    dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com

Ref: RFC 7601 — Message Header Field for Indicating Message Authentication Status
"""

from __future__ import annotations

import re
from typing import Optional

from eti_core.models import AuthResult, AuthStatus


# ---------------------------------------------------------------------------
# Regex de parseo
# ---------------------------------------------------------------------------

# Extrae bloques "mechanism=result ..." para cada mecanismo
_RE_MECHANISM = re.compile(
    r"\b(spf|dkim|dmarc|arc)\s*=\s*([a-zA-Z]+)",
    re.IGNORECASE,
)

# Extrae dominios de cada mecanismo
_RE_DKIM_DOMAIN = re.compile(
    r"header\.i\s*=\s*@?([\w.\-]+)",
    re.IGNORECASE,
)
_RE_DKIM_SELECTOR = re.compile(
    r"header\.s\s*=\s*([\w.\-]+)",
    re.IGNORECASE,
)
_RE_SPF_DOMAIN = re.compile(
    r"smtp\.mailfrom\s*=\s*([\w.\-@]+)",
    re.IGNORECASE,
)
_RE_DMARC_FROM = re.compile(
    r"header\.from\s*=\s*([\w.\-]+)",
    re.IGNORECASE,
)
_RE_DMARC_POLICY = re.compile(
    r"p\s*=\s*(\w+)",
    re.IGNORECASE,
)


def _normalize_status(raw_status: str) -> AuthStatus:
    """Convierte string de resultado a enum AuthStatus."""
    normalized = raw_status.lower().strip()
    try:
        return AuthStatus(normalized)
    except ValueError:
        return AuthStatus.UNKNOWN


def parse_authentication_results(header_value: str) -> AuthResult:
    """
    Parsea el valor de uno o más headers Authentication-Results.

    Args:
        header_value: Valor completo del header (puede ser multiline con \\n).

    Returns:
        AuthResult con los resultados de SPF, DKIM y DMARC.
    """
    if not header_value:
        return AuthResult(raw=header_value)

    result = AuthResult(raw=header_value)

    # Extraer todos los mecanismos y sus resultados
    for match in _RE_MECHANISM.finditer(header_value):
        mechanism = match.group(1).lower()
        status = _normalize_status(match.group(2))

        if mechanism == "spf":
            result.spf = status
            spf_domain_m = _RE_SPF_DOMAIN.search(header_value)
            if spf_domain_m:
                domain = spf_domain_m.group(1)
                # Si tiene @, tomar solo la parte del dominio
                result.spf_domain = domain.split("@")[-1]

        elif mechanism == "dkim":
            result.dkim = status
            dkim_domain_m = _RE_DKIM_DOMAIN.search(header_value)
            if dkim_domain_m:
                result.dkim_domain = dkim_domain_m.group(1)
            dkim_sel_m = _RE_DKIM_SELECTOR.search(header_value)
            if dkim_sel_m:
                result.dkim_selector = dkim_sel_m.group(1)

        elif mechanism == "dmarc":
            result.dmarc = status
            dmarc_from_m = _RE_DMARC_FROM.search(header_value)
            if dmarc_from_m:
                pass  # domain se puede inferir del from_address en EmailHeaders
            policy_m = _RE_DMARC_POLICY.search(header_value)
            if policy_m:
                result.dmarc_policy = policy_m.group(1).upper()

    return result


def parse_all_auth_headers(headers_dict: dict) -> AuthResult:
    """
    Procesa todos los headers de autenticación del correo.
    Maneja el caso donde hay múltiples Authentication-Results (por reenviados).

    Args:
        headers_dict: Dict de headers (lowercase keys).

    Returns:
        AuthResult consolidado.
    """
    # Puede haber múltiples Authentication-Results en un correo reenviado
    auth_headers = headers_dict.get("authentication-results", [])
    if isinstance(auth_headers, str):
        auth_headers = [auth_headers]

    # Tomar el primer Authentication-Results que tenga dkim/spf/dmarc reales
    for header_val in auth_headers:
        result = parse_authentication_results(header_val)
        # Si encontramos resultados no-UNKNOWN, lo usamos
        if result.spf != AuthStatus.UNKNOWN or result.dkim != AuthStatus.UNKNOWN:
            return result

    # Fallback: parsear el primero que haya (aunque sea vacío)
    if auth_headers:
        return parse_authentication_results(auth_headers[0])

    # ── Señales secundarias cuando no hay Authentication-Results ──────────────
    # Gmail a veces omite el header en la respuesta view=om para ciertos correos.
    # Podemos inferir señales de autenticación de otros headers.
    result = AuthResult()  # raw=None → indica que no hay AR completo

    # DKIM-Signature: si el correo contiene una firma DKIM, SPF probablemente pasó
    dkim_sig = headers_dict.get("dkim-signature", None)
    if dkim_sig:
        # La presencia del header DKIM-Signature indica que el remitente firmó
        # (no garantiza que fue verificada, pero es señal positiva)
        result.dkim = AuthStatus.NEUTRAL  # no podemos confirmar pass sin el AR

    # Received-SPF: algunas gateways agregan este header por separado
    received_spf = headers_dict.get("received-spf", None)
    if received_spf:
        spf_str = str(received_spf).lower()
        if "pass" in spf_str:
            result.spf = AuthStatus.PASS
        elif "fail" in spf_str:
            result.spf = AuthStatus.FAIL
        elif "softfail" in spf_str:
            result.spf = AuthStatus.SOFTFAIL
        elif "neutral" in spf_str:
            result.spf = AuthStatus.NEUTRAL

    # X-Google-DKIM-Signature: señal de que Gmail procesó una firma DKIM
    if headers_dict.get("x-google-dkim-signature"):
        if result.dkim == AuthStatus.UNKNOWN:
            result.dkim = AuthStatus.NEUTRAL

    return result


def auth_score(auth: "AuthResult") -> float:
    """
    Calcula un sub-score de autenticación (0.0–1.0).

    Lógica:
    - Authentication-Results ausente (raw=None): neutro 0.3 (no es fail, no sabemos)
    - DKIM pass: +0.4
    - SPF pass: +0.3
    - DMARC pass: +0.3
    - softfail/neutral: mitad del puntaje
    - fail/none: 0
    - UNKNOWN (sin dato): 0 puntos de ese componente, pero no penaliza
    """
    # Si no hay Authentication-Results en absoluto, no podemos evaluar.
    # Es diferente a "fail" — devolvemos mínimo de aprobación (score neutro)
    if auth.raw is None:
        # Señales secundarias: DKIM-Signature o Received-SPF pueden dar crédito parcial
        partial = 0.0
        if auth.dkim in (AuthStatus.PASS, AuthStatus.NEUTRAL):
            partial += 0.2  # crédito parcial por firma DKIM detectada
        if auth.spf == AuthStatus.PASS:
            partial += 0.15  # crédito por SPF detectado en Received-SPF
        elif auth.spf == AuthStatus.NEUTRAL:
            partial += 0.075
        # Mínimo neutro de 0.3 si no hay ninguna señal
        return max(0.3, min(1.0, partial + 0.3))

    score = 0.0

    def _points(status: AuthStatus, full: float) -> float:
        if status == AuthStatus.PASS:
            return full
        elif status in (AuthStatus.SOFTFAIL, AuthStatus.NEUTRAL):
            return full * 0.5
        elif status == AuthStatus.UNKNOWN:
            return 0.0  # sin dato: no suma pero no penaliza
        return 0.0

    score += _points(auth.dkim, 0.4)
    score += _points(auth.spf, 0.3)
    score += _points(auth.dmarc, 0.3)

    return min(1.0, score)
