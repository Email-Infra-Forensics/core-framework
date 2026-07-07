"""
traceroute/ordering.py — Ordenamiento cronológico de saltos SMTP y detección de anomalías.

Después de parsear los Received:, este módulo:
1. Verifica que los timestamps sean coherentes cronológicamente.
2. Detecta saltos "huérfanos" (sin IP, sin timestamp, o con salto temporal inverso).
3. Clasifica saltos sospechosos para alimentar el score ETI.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Optional

from eti_core.models import Hop, HopClassification


# Tolerancia de desfase de timestamp entre saltos contiguos (NTP drift, etc.)
_MAX_BACKWARD_DELTA = timedelta(minutes=10)
# Si un salto está más de este tiempo en el futuro del anterior, es sospechoso
_MAX_FORWARD_DELTA = timedelta(hours=24)


def detect_orphan_hops(hops: list[Hop]) -> list[Hop]:
    """
    Marca saltos huérfanos o anómalos:
    - Sin IP conocida y sin from_host
    - Con timestamp muy en el pasado respecto al salto anterior
    - Con timestamp muy en el futuro (más de 24h)

    Modifica los hops in-place (classification) y los devuelve.
    """
    for i, hop in enumerate(hops):
        reasons = []

        # Sin información de origen
        if not hop.ip and not hop.from_host:
            reasons.append("sin_ip_ni_from")

        # Verificar coherencia temporal con el salto anterior
        if i > 0 and hop.timestamp and hops[i - 1].timestamp:
            delta = hop.timestamp - hops[i - 1].timestamp

            if delta < -_MAX_BACKWARD_DELTA:
                reasons.append(f"timestamp_retrocede_{abs(delta.seconds)}s")

            elif delta > _MAX_FORWARD_DELTA:
                reasons.append(f"timestamp_salto_futuro_{delta.total_seconds():.0f}s")

        if reasons and hop.classification == HopClassification.UNKNOWN:
            hop.classification = HopClassification.ANOMALOUS

    return hops


def sort_hops_by_timestamp(hops: list[Hop]) -> list[Hop]:
    """
    Ordena saltos cronológicamente cuando los timestamps están disponibles.
    Cuando no hay timestamp, mantiene el orden inverso al de aparición
    en el correo (que es la convención SMTP estándar).

    Args:
        hops: Lista de Hop en cualquier orden.

    Returns:
        Lista reordenada con índices actualizados.
    """
    hops_with_ts = [h for h in hops if h.timestamp is not None]
    hops_without_ts = [h for h in hops if h.timestamp is None]

    if hops_with_ts:
        hops_with_ts.sort(key=lambda h: h.timestamp)  # type: ignore[arg-type]

    ordered = hops_with_ts + hops_without_ts
    for i, hop in enumerate(ordered):
        hop.index = i

    return ordered


def summarize_route(hops: list[Hop]) -> dict:
    """
    Genera un resumen de la ruta SMTP para el output del ETI.

    Returns:
        Dict con: total_hops, anomalous_hops, known_esp_hops,
                  has_complete_timestamps, unique_asns
    """
    anomalous = sum(1 for h in hops if h.classification == HopClassification.ANOMALOUS)
    known_esp = sum(1 for h in hops if h.classification == HopClassification.KNOWN_ESP)
    with_ts = sum(1 for h in hops if h.timestamp is not None)
    asns = {h.asn for h in hops if h.asn is not None}

    return {
        "total_hops": len(hops),
        "anomalous_hops": anomalous,
        "known_esp_hops": known_esp,
        "hops_with_timestamp": with_ts,
        "has_complete_timestamps": with_ts == len(hops),
        "unique_asns": sorted(asns),
    }
