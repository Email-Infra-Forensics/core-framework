"""
msgid/__init__.py — Módulo de análisis de Message-ID.
"""
from eti_core.msgid.extractor import MessageIDComponents, extract_domain_from_msgid, extract_msgid_components
from eti_core.msgid.signature import OrgSignature, build_signature, score_against_signature

__all__ = [
    "extract_msgid_components",
    "extract_domain_from_msgid",
    "MessageIDComponents",
    "build_signature",
    "score_against_signature",
    "OrgSignature",
]
