"""
tests/test_traceroute.py — Tests del módulo traceroute.
"""
import pytest
from pathlib import Path
from eti_core.traceroute.parser import parse_eml_file, parse_received_header
from eti_core.traceroute.ordering import detect_orphan_hops, sort_hops_by_timestamp
from eti_core.models import HopClassification

FIXTURES = Path(__file__).parent / "fixtures"


class TestParseReceivedHeader:
    def test_google_format(self):
        raw = "from mail.example.com (mail.example.com [209.85.220.41]) by mx.google.com with ESMTPS; Mon, 1 Jan 2024 12:00:00 +0000"
        hop = parse_received_header(raw, index=0)
        assert hop.ip == "209.85.220.41"
        assert hop.by_host is not None
        assert "google" in (hop.by_host or "").lower()
        assert hop.timestamp is not None

    def test_basic_smtp(self):
        raw = "from smtp.bancochile.cl (smtp.bancochile.cl [190.160.1.10]) by mail-out.bancochile.cl with ESMTP; Mon, 1 Jan 2024 11:59:58 +0000"
        hop = parse_received_header(raw, index=1)
        assert hop.ip == "190.160.1.10"
        assert hop.with_protocol is not None

    def test_no_ip(self):
        raw = "from localhost by mail.example.com with ESMTP; Mon, 1 Jan 2024 12:00:00 +0000"
        hop = parse_received_header(raw, index=0)
        assert hop.ip is None
        assert hop.from_host == "localhost"

    def test_timestamp_parsed(self):
        raw = "from a by b; Mon, 1 Jan 2024 12:00:00 +0000"
        hop = parse_received_header(raw)
        assert hop.timestamp is not None
        assert hop.timestamp.year == 2024


class TestParseEmlFile:
    def test_parse_trusted_eml(self):
        path = FIXTURES / "sample_trusted.eml"
        headers, hops = parse_eml_file(path)
        assert len(hops) >= 2, "El correo trusted debe tener al menos 2 hops"
        assert "message-id" in headers

    def test_parse_suspicious_eml(self):
        path = FIXTURES / "sample_suspicious.eml"
        headers, hops = parse_eml_file(path)
        assert len(hops) >= 1

    def test_hops_chronological_order(self):
        path = FIXTURES / "sample_trusted.eml"
        _, hops = parse_eml_file(path)
        # Verificar que los índices son continuos
        for i, hop in enumerate(hops):
            assert hop.index == i


class TestOrdering:
    def test_detect_orphan_no_ip(self):
        from eti_core.traceroute.parser import parse_received_header
        hop = parse_received_header("from localhost by mail.example.com; Mon, 1 Jan 2024 12:00:00 +0000")
        hops = [hop]
        result = detect_orphan_hops(hops)
        # Hop sin IP pero con from_host no debería ser marcado como ANOMALOUS por defecto
        # (solo si no tiene ni IP ni from_host)
        assert result[0].classification != HopClassification.ANOMALOUS  # tiene from_host

    def test_sort_by_timestamp(self):
        from datetime import datetime, timezone, timedelta
        from eti_core.models import Hop
        t0 = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        hops = [
            Hop(index=0, raw="raw1", timestamp=t0 + timedelta(minutes=2)),
            Hop(index=1, raw="raw2", timestamp=t0),
            Hop(index=2, raw="raw3", timestamp=t0 + timedelta(minutes=1)),
        ]
        sorted_hops = sort_hops_by_timestamp(hops)
        assert sorted_hops[0].timestamp == t0
        assert sorted_hops[1].timestamp == t0 + timedelta(minutes=1)
        assert sorted_hops[2].timestamp == t0 + timedelta(minutes=2)
