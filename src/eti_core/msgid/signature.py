"""
msgid/signature.py — Firma de Message-ID por organización.

A partir de N muestras históricas de Message-ID de una organización,
genera una "firma" que resume el patrón esperado.
Esta firma se usa para comparar correos nuevos contra la línea base.

No usamos regex aprendidos desde cero (frágiles con poca muestra).
En cambio, usamos un perfil de features booleans/numéricos que se
compara con los features del Message-ID entrante → score de similitud.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from eti_core.msgid.extractor import MessageIDComponents, extract_msgid_components


@dataclass
class OrgSignature:
    """Firma de Message-ID para una organización."""

    org_id: str
    sample_count: int = 0

    # Frecuencias de features (0.0–1.0)
    uuid_freq: float = 0.0
    timestamp_compact_freq: float = 0.0
    epoch_ts_freq: float = 0.0
    hex_block_freq: float = 0.0
    counter_freq: float = 0.0

    # Rangos de longitud del local-part
    local_part_length_min: int = 0
    local_part_length_max: int = 0
    local_part_length_mean: float = 0.0

    # Segmentos típicos
    segment_count_min: int = 0
    segment_count_max: int = 0
    segment_count_mean: float = 0.0

    # Dominios observados
    domains: list[str] = field(default_factory=list)

    # Prefijos más frecuentes
    top_prefixes: list[str] = field(default_factory=list)

    # Proveedores (ESPs) detectados
    top_providers: list[str] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def from_json(cls, data: str | dict) -> "OrgSignature":
        d = json.loads(data) if isinstance(data, str) else data
        return cls(**d)

    def save(self, path: Path) -> None:
        path.write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "OrgSignature":
        return cls.from_json(path.read_text(encoding="utf-8"))


def build_signature(org_id: str, msgid_samples: list[str]) -> OrgSignature:
    """
    Construye una OrgSignature a partir de N Message-IDs históricos.

    Args:
        org_id: Identificador de la organización (ej: "bancochile", "falabella").
        msgid_samples: Lista de Message-ID crudos.

    Returns:
        OrgSignature representando el perfil de la organización.
    """
    components = []
    for raw in msgid_samples:
        comp = extract_msgid_components(raw)
        if comp:
            components.append(comp)

    if not components:
        return OrgSignature(org_id=org_id)

    n = len(components)

    # Frecuencias booleanas
    uuid_freq = sum(c.has_uuid for c in components) / n
    ts_compact_freq = sum(c.has_timestamp_compact for c in components) / n
    epoch_ts_freq = sum(c.has_epoch_timestamp for c in components) / n
    hex_block_freq = sum(c.has_hex_block for c in components) / n
    counter_freq = sum(c.has_counter for c in components) / n

    # Longitudes
    lengths = [c.local_part_length for c in components]
    segments = [c.segment_count for c in components]

    # Dominios únicos
    domains = list({c.domain for c in components if c.domain})

    # Prefijos más comunes
    from collections import Counter
    prefixes = [c.prefix for c in components if c.prefix]
    top_prefixes = [p for p, _ in Counter(prefixes).most_common(5)]

    # Proveedores ESP dominantes
    providers = [c.provider for c in components if c.provider and c.provider != "Unknown"]
    top_providers = [p for p, _ in Counter(providers).most_common(3)]

    return OrgSignature(
        org_id=org_id,
        sample_count=n,
        uuid_freq=round(uuid_freq, 3),
        timestamp_compact_freq=round(ts_compact_freq, 3),
        epoch_ts_freq=round(epoch_ts_freq, 3),
        hex_block_freq=round(hex_block_freq, 3),
        counter_freq=round(counter_freq, 3),
        local_part_length_min=min(lengths),
        local_part_length_max=max(lengths),
        local_part_length_mean=round(sum(lengths) / n, 1),
        segment_count_min=min(segments),
        segment_count_max=max(segments),
        segment_count_mean=round(sum(segments) / n, 1),
        domains=sorted(domains),
        top_prefixes=top_prefixes,
        top_providers=top_providers,
    )


def score_against_signature(
    msgid: str,
    signature: OrgSignature,
) -> float:
    """
    Compara un Message-ID contra la firma de una organización.

    Args:
        msgid: Message-ID del correo a analizar.
        signature: Firma de la organización esperada.

    Returns:
        Score de similitud (0.0 = muy diferente, 1.0 = perfecto match).
    """
    comp = extract_msgid_components(msgid)
    if not comp:
        return 0.0

    # Si el sample count es muy bajo, no dar mucha confianza a la firma
    if signature.sample_count < 5:
        return 0.5  # score neutro

    score = 0.0
    factors = 0

    def _bool_match(comp_val: bool, sig_freq: float) -> tuple[float, float]:
        """Retorna (score_obtenido, peso_del_factor)."""
        if sig_freq >= 0.75:
            # Es un feature característico esperado de esta organización
            weight = 2.0
            score_val = 1.0 if comp_val else 0.0
            return score_val * weight, weight
        elif sig_freq <= 0.25:
            # Es un feature raro/no característico
            weight = 1.0
            score_val = 1.0 if not comp_val else 0.0
            return score_val * weight, weight
        else:
            weight = 0.5
            return 0.5 * weight, weight

    total_weighted_score = 0.0
    total_weight = 0.0

    # Comparar features booleanos
    bool_checks = [
        (comp.has_uuid, signature.uuid_freq),
        (comp.has_timestamp_compact, signature.timestamp_compact_freq),
        (comp.has_epoch_timestamp, signature.epoch_ts_freq),
        (comp.has_hex_block, signature.hex_block_freq),
        (comp.has_counter, signature.counter_freq),
    ]
    for val, freq in bool_checks:
        s, w = _bool_match(val, freq)
        total_weighted_score += s
        total_weight += w

    # Verificar longitud del local-part
    if signature.local_part_length_max > 0:
        in_range = (
            signature.local_part_length_min * 0.7
            <= comp.local_part_length
            <= signature.local_part_length_max * 1.3
        )
        w_len = 2.0
        total_weighted_score += (1.0 if in_range else 0.0) * w_len
        total_weight += w_len

    # Verificar dominio conocido (peso alto)
    if signature.domains and comp.domain:
        comp_dom = comp.domain.lower()
        domain_known = any(
            comp_dom == d.lower()
            or comp_dom.endswith("." + d.lower())
            or d.lower().endswith("." + comp_dom)
            for d in signature.domains
        )
        w_dom = 3.0
        total_weighted_score += (1.0 if domain_known else 0.0) * w_dom
        total_weight += w_dom

    # Verificar proveedor (ESP) coherente con la línea base
    if signature.top_providers and comp.provider != "Unknown":
        provider_known = comp.provider in signature.top_providers
        w_prov = 2.0
        total_weighted_score += (1.0 if provider_known else 0.0) * w_prov
        total_weight += w_prov

    if total_weight == 0:
        return 0.5

    return round(total_weighted_score / total_weight, 3)
