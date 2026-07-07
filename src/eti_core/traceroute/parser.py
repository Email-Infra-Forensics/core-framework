"""
traceroute/parser.py — Parser de headers Received: de correos SMTP.

Parsea la cadena Received: de cada salto, tolerante a variaciones
de formato entre distintos MTAs (Google, Yahoo, Outlook, Amazon SES,
Postfix, Sendmail, Exchange).

Referencia: RFC 5321 §4.4, RFC 5322 §3.6.7
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser, Parser
from pathlib import Path
from typing import Optional

from eti_core.models import Hop

# ---------------------------------------------------------------------------
# Patrones regex para parsear el header Received:
# ---------------------------------------------------------------------------

# IP v4 e IPv6 en distintos formatos de MTAs
_RE_IPV4 = re.compile(
    r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
)
_RE_IPV6 = re.compile(
    r"\[?((?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4})\]?"
)

# "from host.example.com" o "from [1.2.3.4]" al inicio del valor
_RE_FROM = re.compile(
    r"\bfrom\s+(\S+)",
    re.IGNORECASE,
)

# "by host.example.com" — servidor que recibió
_RE_BY = re.compile(
    r"\bby\s+(\S+)",
    re.IGNORECASE,
)

# "with ESMTP" / "with LMTP" / etc.
_RE_WITH = re.compile(
    r"\bwith\s+(\S+)",
    re.IGNORECASE,
)

# Timestamp al final: ";  Mon, 1 Jan 2024 12:00:00 +0000"
_RE_TIMESTAMP = re.compile(
    r";\s*(.+)$",
    re.DOTALL,
)

# Formatos de timestamp comunes en MTAs
_TIMESTAMP_FORMATS = [
    "%a, %d %b %Y %H:%M:%S %z",      # RFC 2822 estándar
    "%d %b %Y %H:%M:%S %z",           # sin día de semana
    "%a, %d %b %Y %H:%M:%S %Z",       # con nombre de zona
    "%d %b %Y %H:%M:%S %Z",
    "%a, %d %b %Y %H:%M %z",          # sin segundos
]


def _parse_timestamp(raw_ts: str) -> Optional[datetime]:
    """Intenta parsear un string de timestamp con múltiples formatos."""
    if not raw_ts:
        return None

    # Limpiar caracteres problemáticos y normalizar espacios múltiples
    cleaned = re.sub(r"\s+", " ", raw_ts.strip())
    # Remover comentarios entre paréntesis (comunes en Received:)
    cleaned = re.sub(r"\([^)]*\)", "", cleaned).strip()

    for fmt in _TIMESTAMP_FORMATS:
        try:
            dt = datetime.strptime(cleaned, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue

    return None


def _extract_ip(text: str) -> Optional[str]:
    """Extrae la primera IP (preferentemente de corchetes [IP]) del texto."""
    # Buscar primero en formato [IP] que suele ser la IP real del cliente
    bracketed = re.search(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", text)
    if bracketed:
        return bracketed.group(1)

    # IPv6 entre corchetes
    bracketed_v6 = re.search(r"\[([0-9a-fA-F:]+)\]", text)
    if bracketed_v6:
        candidate = bracketed_v6.group(1)
        if ":" in candidate and len(candidate) > 4:
            return candidate

    # Fallback: primera IPv4 en el texto
    m = _RE_IPV4.search(text)
    if m:
        ip = m.group(1)
        # Filtrar IPs de loopback/privadas si queremos ser estrictos
        return ip

    return None


def parse_received_header(raw: str, index: int = 0) -> Hop:
    """
    Parsea un header Received: completo y devuelve un Hop.

    Args:
        raw: Valor completo del header Received: (sin el nombre del header).
        index: Posición del hop en la cadena (0 = más antiguo).

    Returns:
        Hop poblado con todos los campos que se pudieron extraer.
    """
    from_match = _RE_FROM.search(raw)
    by_match = _RE_BY.search(raw)
    with_match = _RE_WITH.search(raw)
    ts_match = _RE_TIMESTAMP.search(raw)

    from_host = from_match.group(1).rstrip(";") if from_match else None
    by_host = by_match.group(1).rstrip(";") if by_match else None
    with_protocol = with_match.group(1).rstrip(";") if with_match else None

    # El timestamp viene después del último ";"
    timestamp = None
    if ts_match:
        timestamp = _parse_timestamp(ts_match.group(1))

    # Extraer IP — del from_host si tiene corchetes, o buscar en el raw
    ip = None
    if from_host and ("[" in from_host or re.match(r"\d{1,3}\.", from_host)):
        ip = _extract_ip(from_host)
    if not ip:
        ip = _extract_ip(raw)

    # Limpiar from_host si tenía IP con corchetes
    if from_host:
        from_host = re.sub(r"\s*\[.*?\]\s*", "", from_host).strip() or from_host

    return Hop(
        index=index,
        from_host=from_host,
        by_host=by_host,
        with_protocol=with_protocol,
        ip=ip,
        timestamp=timestamp,
        raw=raw,
    )


def parse_received_headers_from_text(headers_text: str) -> list[Hop]:
    """
    Dado un bloque de headers de correo como texto, extrae y parsea
    todos los headers Received: en orden (más reciente primero, como
    aparecen en el correo).

    Los headers Received: se apilan en orden inverso al tiempo:
    el primero en el correo es el más reciente.
    Esta función los devuelve reordenados cronológicamente (más viejo = index 0).

    Args:
        headers_text: String con los headers del correo (solo headers, no body).

    Returns:
        Lista de Hop ordenada cronológicamente.
    """
    msg = Parser(policy=policy.default).parsestr(headers_text, headersonly=True)
    received_raw = msg.get_all("Received") or []

    # Parsear cada uno (en el orden que vienen: más reciente primero)
    hops_reversed = [
        parse_received_header(raw, index=i)
        for i, raw in enumerate(received_raw)
    ]

    # Reordenar: el origen (más viejo) pasa a index 0
    hops_chronological = list(reversed(hops_reversed))
    for i, hop in enumerate(hops_chronological):
        hop.index = i

    return hops_chronological


def parse_eml_file(path: Path) -> tuple[dict, list[Hop]]:
    """
    Lee un archivo .eml y devuelve sus headers como dict y los hops parseados.

    Args:
        path: Ruta al archivo .eml

    Returns:
        Tuple (headers_dict, hops_list)
    """
    raw_bytes = path.read_bytes()
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    # Extraer headers como dict (puede haber múltiples del mismo nombre)
    headers = {}
    for key in set(msg.keys()):
        values = msg.get_all(key)
        headers[key.lower()] = values if len(values) > 1 else values[0]

    received_raw = msg.get_all("Received") or []
    hops_reversed = [
        parse_received_header(raw, index=i)
        for i, raw in enumerate(received_raw)
    ]
    hops = list(reversed(hops_reversed))
    for i, hop in enumerate(hops):
        hop.index = i

    return headers, hops
