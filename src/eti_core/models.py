"""
models.py — Contratos de datos del framework ETI.

Define los tipos centrales que circulan entre módulos:
  - Hop: un salto SMTP en el traceroute de la ruta del correo.
  - AuthResult: resultado de autenticación SPF/DKIM/DMARC.
  - EmailHeaders: headers completos de un correo parseado.
  - ScoreBreakdown: explicación de cada componente del ETI.
  - TrustScore: resultado final del análisis ETI.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums de dominio
# ---------------------------------------------------------------------------

class AuthStatus(str, Enum):
    """Resultado de una verificación de autenticación."""
    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"
    UNKNOWN = "unknown"


class HopClassification(str, Enum):
    """Clasificación de un salto SMTP según su ASN."""
    KNOWN_ESP = "known_esp"          # Proveedor conocido (Google, Amazon SES, Sendgrid…)
    TRANSIT = "transit"              # Infraestructura de tránsito
    UNKNOWN = "unknown"              # No identificado
    ANOMALOUS = "anomalous"          # Salto huérfano o con IP inconsistente


# ---------------------------------------------------------------------------
# Modelos base
# ---------------------------------------------------------------------------

class Hop(BaseModel):
    """Un salto en el traceroute SMTP de un correo."""

    index: int = Field(description="Posición en la cadena (0 = más antiguo / origen)")
    from_host: Optional[str] = Field(None, description="Host o IP declarado en 'from'")
    by_host: Optional[str] = Field(None, description="Host que recibió el mensaje ('by')")
    with_protocol: Optional[str] = Field(None, description="Protocolo (esmtp, lmtp, etc.)")
    ip: Optional[str] = Field(None, description="IP extraída del hop (IPv4 o IPv6)")
    timestamp: Optional[datetime] = Field(None, description="Timestamp del salto (parseado)")
    raw: str = Field(description="Línea Received: completa sin parsear")

    # Enriquecimiento — se llena después por enrichment/
    asn: Optional[int] = Field(None, description="Número de sistema autónomo")
    asn_org: Optional[str] = Field(None, description="Organización del ASN")
    classification: HopClassification = Field(
        HopClassification.UNKNOWN,
        description="Clasificación del salto según su ASN",
    )


class AuthResult(BaseModel):
    """Resultado de un mecanismo de autenticación de correo."""

    spf: AuthStatus = AuthStatus.UNKNOWN
    spf_domain: Optional[str] = None

    dkim: AuthStatus = AuthStatus.UNKNOWN
    dkim_domain: Optional[str] = None
    dkim_selector: Optional[str] = None

    dmarc: AuthStatus = AuthStatus.UNKNOWN
    dmarc_policy: Optional[str] = None

    raw: Optional[str] = Field(None, description="Header Authentication-Results completo")


class EmailHeaders(BaseModel):
    """Headers completos de un correo, listos para análisis forense.

    Este es el contrato de intercambio entre data-curator y core-framework.
    Los campos de PII (from_address, to_address) vienen hasheados desde data-curator.
    """

    # Identidad
    message_id: Optional[str] = Field(None, description="Message-ID del correo")
    from_address: str = Field(description="Dirección del remitente (hashed en PII)")
    to_address: str = Field(description="Dirección del destinatario (hashed en PII)")
    subject_hash: Optional[str] = Field(None, description="Hash del asunto (no el texto plano)")
    date: Optional[datetime] = Field(None, description="Fecha del correo (header Date:)")

    # Ruta SMTP
    hops: list[Hop] = Field(default_factory=list, description="Saltos en orden cronológico")

    # Autenticación
    auth: AuthResult = Field(default_factory=AuthResult)

    # Metadata de origen (rellena por data-curator)
    source_dataset: Optional[str] = Field(None, description="Dataset de origen (enron, kaggle…)")
    source_file: Optional[str] = Field(None, description="Ruta original del .eml/.mbox")
    curator_version: Optional[str] = Field(None, description="Versión de data-curator que generó esto")

    # Metadata de dominio (inferido del Message-ID / from)
    sender_domain: Optional[str] = Field(None, description="Dominio del remitente (sin hash)")
    org_id: Optional[str] = Field(None, description="ID normalizado de la organización emisora")


# ---------------------------------------------------------------------------
# Resultado ETI
# ---------------------------------------------------------------------------

class ScoreBreakdown(BaseModel):
    """Desglose explicable del ETI por componente."""

    # Sub-scores (0.0 – 1.0)
    asn_consistency: float = Field(0.0, ge=0.0, le=1.0,
        description="¿El ASN coincide con la línea base de la organización?")
    msgid_match: float = Field(0.0, ge=0.0, le=1.0,
        description="¿El Message-ID matchea la firma conocida?")
    auth_validity: float = Field(0.0, ge=0.0, le=1.0,
        description="¿SPF/DKIM/DMARC pasan y son consistentes?")

    # Factores de contexto
    hop_count: int = Field(0, description="Número de saltos en la ruta")
    anomalous_hops: int = Field(0, description="Número de saltos clasificados como anómalos")
    known_esp_hops: int = Field(0, description="Saltos en infraestructura ESP conocida")

    # Razones legibles
    reasons: list[str] = Field(default_factory=list,
        description="Lista de razones que explican el score")


class TrustScore(BaseModel):
    """Resultado final del análisis ETI para un correo."""

    # Score final (0–100; 100 = totalmente confiable)
    eti: float = Field(description="Email Trust Index (0–100)", ge=0.0, le=100.0)

    # Clasificación cualitativa
    label: str = Field(description="Etiqueta: trusted / suspicious / anomalous")

    # Desglose
    breakdown: ScoreBreakdown = Field(default_factory=ScoreBreakdown)

    # Metadatos del análisis
    message_id: Optional[str] = None
    sender_domain: Optional[str] = None
    analyzed_at: Optional[datetime] = None
    framework_version: str = "0.1.0"

    @property
    def is_trusted(self) -> bool:
        return self.eti >= 70.0

    @property
    def is_suspicious(self) -> bool:
        return 40.0 <= self.eti < 70.0

    @property
    def is_anomalous(self) -> bool:
        return self.eti < 40.0
