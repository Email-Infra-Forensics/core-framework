"""
traceroute/__init__.py — Módulo de traceroute SMTP.
"""
from eti_core.traceroute.ordering import detect_orphan_hops, sort_hops_by_timestamp, summarize_route
from eti_core.traceroute.parser import parse_eml_file, parse_received_header, parse_received_headers_from_text

__all__ = [
    "parse_received_header",
    "parse_received_headers_from_text",
    "parse_eml_file",
    "detect_orphan_hops",
    "sort_hops_by_timestamp",
    "summarize_route",
]
