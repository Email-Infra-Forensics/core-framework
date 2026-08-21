"""
scoring/eti.py — Algoritmo Email Trust Index (ETI).

Calcula un puntaje de confianza (0–100) para un correo basado en:
  1. Consistencia de infraestructura (ASN / proveedor conocido)
  2. Match del Message-ID con la firma de la organización
  3. Validez de autenticación SPF/DKIM/DMARC

El algoritmo es lineal y explicable: suma ponderada de sub-scores,
con penalizaciones por condiciones adicionales.
Los pesos son configurables vía weights.yaml sin tocar código.

Diseño deliberadamente simple y auditable para contexto académico.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

from eti_core.auth.spf_dkim_dmarc import auth_score
from eti_core.models import (
    AuthResult,
    AuthStatus,
    EmailHeaders,
    Hop,
    HopClassification,
    ScoreBreakdown,
    TrustScore,
)
from eti_core.msgid.signature import OrgSignature, score_against_signature

# Ruta al archivo de pesos (relativa al paquete instalado)
_DEFAULT_WEIGHTS_PATH = Path(__file__).parent.parent.parent.parent / "weights.yaml"


def _load_weights(path: Optional[Path] = None) -> dict:
    """Carga la configuración de pesos desde YAML."""
    weights_path = path or _DEFAULT_WEIGHTS_PATH

    if not weights_path.exists():
        # Defaults si no hay archivo
        return {
            "weights": {"asn_consistency": 0.40, "msgid_match": 0.30, "auth_validity": 0.30},
            "thresholds": {"trusted": 70, "suspicious": 40},
            "penalties": {
                "anomalous_hop_per_hop": 5.0,
                "no_auth_results_header": 10.0,
                "all_unknown_asns": 15.0,
            },
        }

    with open(weights_path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def compute_asn_score(
    hops: list[Hop],
    auth_pass: bool = False,
) -> tuple[float, list[str]]:
    """
    Sub-score de consistencia de infraestructura (0.0–1.0).

    Lógica:
    - Proporción de hops con ASN conocido (ESP o transit), IP privada interna o SPF validado.
    - Penalización adicional por hops ANOMALOUS.

    Returns:
        Tuple (score, lista de razones).
    """
    if not hops:
        return 0.5, ["sin_hops_disponibles"]

    reasons = []
    # Contar como válidos los saltos que son KNOWN_ESP, TRANSIT, tienen ASN público o si SPF pasó
    valid_count = 0
    total = len(hops)
    anomalous = sum(1 for h in hops if h.classification == HopClassification.ANOMALOUS)

    for h in hops:
        if (
            h.classification in (HopClassification.KNOWN_ESP, HopClassification.TRANSIT)
            or h.asn is not None
        ):
            valid_count += 1
        elif auth_pass:
            # Si el correo superó la autenticación SPF/DKIM formalmente, la infraestructura está validada por la entidad
            valid_count += 1

    base_score = valid_count / total

    if anomalous > 0:
        reasons.append(f"{anomalous}_hops_anomalos")
        base_score = max(0.0, base_score - (anomalous * 0.15))

    if valid_count == 0:
        reasons.append("todos_asns_desconocidos")

    # Bonus si al menos la mitad son ESPs conocidos o infraestructura verificada
    known_esp = sum(1 for h in hops if h.classification == HopClassification.KNOWN_ESP)
    if known_esp > 0:
        reasons.append(f"infraestructura_ESP_verificada: {known_esp}/{total}")
        base_score = min(1.0, base_score * 1.1)

    return round(min(1.0, max(0.0, base_score)), 3), reasons


def compute_msgid_score(
    msgid: Optional[str],
    org_signature: Optional[OrgSignature],
) -> tuple[float, list[str]]:
    """
    Sub-score de Message-ID (0.0–1.0).

    Returns:
        Tuple (score, lista de razones).
    """
    reasons = []

    if not msgid:
        reasons.append("sin_message_id")
        return 0.0, reasons

    if not org_signature:
        reasons.append("sin_firma_de_organizacion")
        return 0.5, reasons  # Score neutro sin línea base

    if org_signature.sample_count < 5:
        reasons.append("firma_con_pocas_muestras")
        return 0.5, reasons

    score = score_against_signature(msgid, org_signature)
    if score >= 0.8:
        reasons.append("message_id_coincide_con_firma")
    elif score >= 0.5:
        reasons.append("message_id_parcialmente_coincide")
    else:
        reasons.append("message_id_no_coincide_con_firma")

    return score, reasons


def compute_auth_score(auth: AuthResult) -> tuple[float, list[str]]:
    """
    Sub-score de autenticación SPF/DKIM/DMARC (0.0–1.0).

    Returns:
        Tuple (score, lista de razones).
    """
    from eti_core.models import AuthStatus

    reasons = []
    score = auth_score(auth)

    if auth.dkim == AuthStatus.PASS:
        reasons.append("dkim_pass")
    elif auth.dkim == AuthStatus.FAIL:
        reasons.append("dkim_fail")

    if auth.spf == AuthStatus.PASS:
        reasons.append("spf_pass")
    elif auth.spf == AuthStatus.FAIL:
        reasons.append("spf_fail")

    if auth.dmarc == AuthStatus.PASS:
        reasons.append("dmarc_pass")
    elif auth.dmarc == AuthStatus.FAIL:
        reasons.append("dmarc_fail")

    if auth.raw is None:
        reasons.append("sin_header_authentication_results")

    return round(score, 3), reasons


def calculate_eti(
    headers: EmailHeaders,
    org_signature: Optional[OrgSignature] = None,
    weights_path: Optional[Path] = None,
    sender_in_db: bool = False,
    spoofing_detected: bool = False,
) -> TrustScore:
    """
    Calcula el Email Trust Index para un correo.

    Args:
        headers: Headers del correo (salida de data-curator o del parser).
        org_signature: Firma de la organización emisora (opcional).
        weights_path: Ruta a weights.yaml (usa el default si no se provee).
        sender_in_db: Si el dominio emisor está registrado en nuestra DB.
        spoofing_detected: Si se detectó intento de suplantación de identidad.

    Returns:
        TrustScore con ETI, label y breakdown explicable.
    """
    config = _load_weights(weights_path)
    w = config["weights"]
    penalties_cfg = config.get("penalties", {})
    thresholds = config.get("thresholds", {"trusted": 70, "suspicious": 40})

    # Si se detectó spoofing, cortocircuitamos con penalización severa
    if spoofing_detected:
        all_reasons = ["[SPOOFING] display_name_suplanta_entidad_conocida"]
        breakdown = ScoreBreakdown(
            asn_consistency=0.0,
            msgid_match=0.0,
            auth_validity=0.0,
            hop_count=len(headers.hops),
            anomalous_hops=len(headers.hops),
            known_esp_hops=0,
            reasons=all_reasons,
        )
        return TrustScore(
            eti=0.0,
            label="phishing_alert",
            breakdown=breakdown,
            message_id=headers.message_id,
            sender_domain=headers.sender_domain,
            analyzed_at=datetime.now(tz=timezone.utc),
        )

    # Calcular sub-scores
    a_score, auth_reasons = compute_auth_score(headers.auth)
    auth_pass = headers.auth.spf == AuthStatus.PASS or headers.auth.dkim == AuthStatus.PASS
    asn_score, asn_reasons = compute_asn_score(headers.hops, auth_pass=auth_pass)
    msgid_score, msgid_reasons = compute_msgid_score(headers.message_id, org_signature)

    # Si el emisor NO está en la DB, aplicar mínimos de aprobación:
    # ASN y MSG-ID quedan en el neutro (0.5) pero el score de autenticación
    # se respeta como real (si viene SPF/DKIM reales).
    if not sender_in_db:
        if asn_score > 0.5:
            asn_score = 0.5
            asn_reasons.append("entidad_no_registrada_en_db_asn_limitado")
        if msgid_score > 0.5:
            msgid_score = 0.5
            msgid_reasons.append("entidad_no_registrada_en_db_msgid_limitado")

    # ETI base: suma ponderada (0–100)
    eti_raw = (
        asn_score * w["asn_consistency"]
        + msgid_score * w["msgid_match"]
        + a_score * w["auth_validity"]
    ) * 100.0

    # Penalizaciones
    anomalous_hops = sum(1 for h in headers.hops if h.classification == HopClassification.ANOMALOUS)
    eti_raw -= anomalous_hops * penalties_cfg.get("anomalous_hop_per_hop", 5.0)

    # Nota: la ausencia de Authentication-Results ya está penalizada dentro
    # de auth_score (devuelve 0.3 neutro en lugar de 1.0 por auth pass).
    # No aplicamos penalización adicional para evitar doble castigo.

    all_unknown = all(h.asn is None for h in headers.hops) and len(headers.hops) > 0
    if all_unknown:
        eti_raw -= penalties_cfg.get("all_unknown_asns", 15.0)

    eti_final = max(0.0, min(100.0, eti_raw))

    # Clasificación
    if eti_final >= thresholds["trusted"]:
        label = "trusted"
    elif eti_final >= thresholds["suspicious"]:
        label = "suspicious"
    else:
        label = "anomalous"

    # Consolidar razones
    all_reasons = (
        [f"[ASN] {r}" for r in asn_reasons]
        + [f"[MSGID] {r}" for r in msgid_reasons]
        + [f"[AUTH] {r}" for r in auth_reasons]
    )

    known_esp = sum(1 for h in headers.hops if h.classification == HopClassification.KNOWN_ESP)

    breakdown = ScoreBreakdown(
        asn_consistency=asn_score,
        msgid_match=msgid_score,
        auth_validity=a_score,
        hop_count=len(headers.hops),
        anomalous_hops=anomalous_hops,
        known_esp_hops=known_esp,
        reasons=all_reasons,
    )

    return TrustScore(
        eti=round(eti_final, 2),
        label=label,
        breakdown=breakdown,
        message_id=headers.message_id,
        sender_domain=headers.sender_domain,
        analyzed_at=datetime.now(tz=timezone.utc),
    )
