"""
msgid/extractor.py — Extracción de patrones sintácticos de Message-ID.

El Message-ID tiene la forma:  <local-part@domain>
El local-part es donde viven las firmas de cada organización:
  - UUIDs: "550e8400-e29b-41d4-a716-446655440000@example.com"
  - Timestamps embebidos: "20240101120000.12345@example.com"
  - Contadores: "msg-0042-suffix@example.com"
  - Formatos propietarios de ESPs: "CAHp...@mail.gmail.com"

Este módulo extrae componentes del local-part para análisis posterior.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Regex de componentes comunes en Message-ID local-parts
# ---------------------------------------------------------------------------

_RE_MSGID = re.compile(r"<([^@>]+)@([^>]+)>")  # Extrae local-part y dominio

# Tipos de tokens en el local-part
_RE_UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)
_RE_TIMESTAMP_COMPACT = re.compile(r"\b(20\d{2}[01]\d[0-3]\d[0-2]\d[0-5]\d[0-5]\d)\b")
_RE_TIMESTAMP_EPOCH = re.compile(r"\b(1[5-9]\d{8}|[2-9]\d{9})\b")  # Unix epoch razonable
_RE_HEX_BLOCK = re.compile(r"\b[0-9a-fA-F]{16,}\b")
_RE_COUNTER = re.compile(r"\b\d{4,10}\b")
_RE_SEPARATOR = re.compile(r"[.\-_+]")


@dataclass
class MessageIDComponents:
    """Componentes extraídos de un Message-ID."""
    raw: str
    local_part: Optional[str] = None
    domain: Optional[str] = None

    # Tipos de tokens detectados
    has_uuid: bool = False
    has_timestamp_compact: bool = False
    has_epoch_timestamp: bool = False
    has_hex_block: bool = False
    has_counter: bool = False

    # Separadores usados en el local-part
    separators: list[str] = field(default_factory=list)

    # Número de segmentos (split por separadores)
    segment_count: int = 0

    # Longitud del local-part
    local_part_length: int = 0

    # Prefijo literal (ej: "msg-", "CAHp", etc.)
    prefix: Optional[str] = None

    def to_feature_vector(self) -> dict:
        """Devuelve features para análisis/clustering."""
        return {
            "has_uuid": int(self.has_uuid),
            "has_timestamp_compact": int(self.has_timestamp_compact),
            "has_epoch_timestamp": int(self.has_epoch_timestamp),
            "has_hex_block": int(self.has_hex_block),
            "has_counter": int(self.has_counter),
            "segment_count": self.segment_count,
            "local_part_length": self.local_part_length,
            "domain": self.domain or "",
            "prefix": self.prefix or "",
            "separators": ".".join(sorted(set(self.separators))),
        }


def extract_msgid_components(raw_msgid: str) -> Optional[MessageIDComponents]:
    """
    Extrae componentes de un Message-ID crudo.

    Args:
        raw_msgid: Valor del header Message-ID (ej: "<abc@example.com>").

    Returns:
        MessageIDComponents o None si el formato es inválido.
    """
    if not raw_msgid or not raw_msgid.strip():
        return None

    raw_msgid = raw_msgid.strip()

    # Parsear local-part y dominio
    m = _RE_MSGID.match(raw_msgid)
    if not m:
        # Intentar sin ángulos
        if "@" in raw_msgid:
            parts = raw_msgid.split("@", 1)
            local_part = parts[0].strip("<> ")
            domain = parts[1].strip("<> ")
        else:
            return None
    else:
        local_part = m.group(1)
        domain = m.group(2)

    comp = MessageIDComponents(
        raw=raw_msgid,
        local_part=local_part,
        domain=domain,
        local_part_length=len(local_part),
    )

    # Detectar tipos de tokens
    comp.has_uuid = bool(_RE_UUID.search(local_part))
    comp.has_timestamp_compact = bool(_RE_TIMESTAMP_COMPACT.search(local_part))
    comp.has_epoch_timestamp = bool(_RE_TIMESTAMP_EPOCH.search(local_part))
    comp.has_hex_block = bool(_RE_HEX_BLOCK.search(local_part))
    comp.has_counter = bool(_RE_COUNTER.search(local_part))

    # Separadores
    comp.separators = list(set(_RE_SEPARATOR.findall(local_part)))

    # Segmentos (dividir por separadores)
    segments = re.split(r"[.\-_+]", local_part)
    comp.segment_count = len([s for s in segments if s])

    # Prefijo literal (primeros chars no-numéricos)
    prefix_m = re.match(r"^([a-zA-Z]{2,6})", local_part)
    if prefix_m:
        comp.prefix = prefix_m.group(1)

    return comp


def extract_domain_from_msgid(raw_msgid: str) -> Optional[str]:
    """Extrae el dominio del Message-ID."""
    comp = extract_msgid_components(raw_msgid)
    return comp.domain if comp else None
