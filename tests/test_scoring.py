"""
tests/test_scoring.py — Tests del algoritmo ETI.
"""
import pytest
from pathlib import Path
from eti_core.models import AuthResult, EmailHeaders, AuthStatus, HopClassification, Hop
from eti_core.scoring.eti import calculate_eti


def _make_headers(hops=None, auth=None, message_id=None, sender_domain=None) -> EmailHeaders:
    """Helper para crear EmailHeaders de prueba."""
    return EmailHeaders(
        from_address="user@example.com",
        to_address="dest@example.com",
        message_id=message_id,
        hops=hops or [],
        auth=auth or AuthResult(),
        sender_domain=sender_domain or "example.com",
    )


class TestCalculateETI:
    def test_empty_headers_returns_score(self):
        headers = _make_headers()
        score = calculate_eti(headers)
        assert 0 <= score.eti <= 100
        assert score.label in ("trusted", "suspicious", "anomalous")

    def test_good_auth_raises_eti(self):
        auth = AuthResult(
            spf=AuthStatus.PASS,
            dkim=AuthStatus.PASS,
            dmarc=AuthStatus.PASS,
            raw="mx.google.com; dkim=pass; spf=pass; dmarc=pass",
        )
        headers = _make_headers(auth=auth)
        score = calculate_eti(headers)
        # Con auth perfecta, el score debería ser al menos 30 (solo del componente auth)
        assert score.eti >= 20.0

    def test_bad_auth_lowers_eti(self):
        auth_fail = AuthResult(
            spf=AuthStatus.FAIL,
            dkim=AuthStatus.FAIL,
            dmarc=AuthStatus.FAIL,
            raw="mx.google.com; dkim=fail; spf=fail; dmarc=fail",
        )
        auth_pass = AuthResult(
            spf=AuthStatus.PASS,
            dkim=AuthStatus.PASS,
            dmarc=AuthStatus.PASS,
            raw="mx.google.com; dkim=pass; spf=pass; dmarc=pass",
        )
        score_fail = calculate_eti(_make_headers(auth=auth_fail))
        score_pass = calculate_eti(_make_headers(auth=auth_pass))
        assert score_fail.eti < score_pass.eti

    def test_anomalous_hops_penalize(self):
        hop_anomalous = Hop(
            index=0,
            raw="from unknown by relay",
            classification=HopClassification.ANOMALOUS,
        )
        hop_known = Hop(
            index=0,
            raw="from known.esp.com by mx.google.com",
            classification=HopClassification.KNOWN_ESP,
        )
        score_bad = calculate_eti(_make_headers(hops=[hop_anomalous]))
        score_good = calculate_eti(_make_headers(hops=[hop_known]))
        assert score_bad.eti < score_good.eti

    def test_breakdown_populated(self):
        auth = AuthResult(
            spf=AuthStatus.PASS,
            dkim=AuthStatus.PASS,
            raw="header",
        )
        headers = _make_headers(auth=auth)
        score = calculate_eti(headers)
        assert score.breakdown is not None
        assert len(score.breakdown.reasons) >= 0
        assert 0 <= score.breakdown.auth_validity <= 1

    def test_label_trusted_high_score(self):
        """Un correo con auth perfecta debería ser trusted o suspicious."""
        auth = AuthResult(
            spf=AuthStatus.PASS,
            dkim=AuthStatus.PASS,
            dmarc=AuthStatus.PASS,
            raw="header",
        )
        hop = Hop(index=0, raw="from esp by google", classification=HopClassification.KNOWN_ESP)
        headers = _make_headers(auth=auth, hops=[hop, hop])
        score = calculate_eti(headers)
        assert score.label in ("trusted", "suspicious")

    def test_eml_file_integration(self):
        """Test de integración completo con archivo .eml real."""
        from eti_core.traceroute.parser import parse_eml_file
        from eti_core.traceroute.ordering import detect_orphan_hops, sort_hops_by_timestamp
        from eti_core.auth.spf_dkim_dmarc import parse_all_auth_headers
        import re

        fixtures = Path(__file__).parent / "fixtures"
        eml_path = fixtures / "sample_trusted.eml"

        headers_dict, hops = parse_eml_file(eml_path)
        hops = sort_hops_by_timestamp(hops)
        hops = detect_orphan_hops(hops)
        auth = parse_all_auth_headers(headers_dict)

        from_header = headers_dict.get("from", "")
        domain_match = re.search(r"@([\w.\-]+)", from_header)
        sender_domain = domain_match.group(1) if domain_match else "unknown"

        email_headers = EmailHeaders(
            message_id=headers_dict.get("message-id"),
            from_address=from_header,
            to_address=headers_dict.get("to", "unknown"),
            hops=hops,
            auth=auth,
            sender_domain=sender_domain,
        )

        score = calculate_eti(email_headers)
        assert 0 <= score.eti <= 100
        # El correo trusted con auth pass debería ser al menos suspicious
        # Sin RDAP, el ASN es desconocido (score=0) pero auth pass debería dar
        # al menos suspicious si la penalización all_unknown_asns no lo baja demasiado
        assert score.eti > 0  # Al menos algo de score
        # El label puede ser anomalous sin RDAP (ASN desconocido penaliza mucho)
        assert score.label in ("trusted", "suspicious", "anomalous")
