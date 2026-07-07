"""
scoring/__init__.py — Módulo de scoring ETI.
"""
from eti_core.scoring.eti import calculate_eti, compute_asn_score, compute_auth_score, compute_msgid_score

__all__ = [
    "calculate_eti",
    "compute_asn_score",
    "compute_msgid_score",
    "compute_auth_score",
]
