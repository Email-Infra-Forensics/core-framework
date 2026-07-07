"""
auth/__init__.py — Módulo de autenticación SPF/DKIM/DMARC.
"""
from eti_core.auth.spf_dkim_dmarc import parse_authentication_results

__all__ = ["parse_authentication_results"]
