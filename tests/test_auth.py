"""
tests/test_auth.py — Tests del parser Authentication-Results.
"""
import pytest
from eti_core.auth.spf_dkim_dmarc import parse_authentication_results, auth_score
from eti_core.models import AuthStatus


class TestParseAuthResults:
    def test_all_pass(self):
        header = (
            "mx.google.com; "
            "dkim=pass header.i=@example.com header.s=selector1; "
            "spf=pass smtp.mailfrom=user@example.com; "
            "dmarc=pass (p=REJECT) header.from=example.com"
        )
        result = parse_authentication_results(header)
        assert result.dkim == AuthStatus.PASS
        assert result.spf == AuthStatus.PASS
        assert result.dmarc == AuthStatus.PASS
        assert result.dkim_domain == "example.com"
        assert result.spf_domain == "example.com"

    def test_all_fail(self):
        header = (
            "mx.google.com; "
            "dkim=fail; "
            "spf=fail; "
            "dmarc=fail"
        )
        result = parse_authentication_results(header)
        assert result.dkim == AuthStatus.FAIL
        assert result.spf == AuthStatus.FAIL
        assert result.dmarc == AuthStatus.FAIL

    def test_softfail(self):
        header = "mx.google.com; spf=softfail smtp.mailfrom=user@example.com"
        result = parse_authentication_results(header)
        assert result.spf == AuthStatus.SOFTFAIL

    def test_empty_header(self):
        result = parse_authentication_results("")
        assert result.dkim == AuthStatus.UNKNOWN
        assert result.spf == AuthStatus.UNKNOWN

    def test_dkim_selector(self):
        header = "mx.google.com; dkim=pass header.i=@example.com header.s=myselector"
        result = parse_authentication_results(header)
        assert result.dkim_selector == "myselector"


class TestAuthScore:
    def test_all_pass_score(self):
        from eti_core.models import AuthResult
        auth = AuthResult(
            spf=AuthStatus.PASS,
            dkim=AuthStatus.PASS,
            dmarc=AuthStatus.PASS,
            raw="mx.google.com; dkim=pass; spf=pass; dmarc=pass",
        )
        score = auth_score(auth)
        assert score == pytest.approx(1.0)

    def test_all_fail_score(self):
        from eti_core.models import AuthResult
        auth = AuthResult(
            spf=AuthStatus.FAIL,
            dkim=AuthStatus.FAIL,
            dmarc=AuthStatus.FAIL,
            raw="mx.google.com; dkim=fail; spf=fail; dmarc=fail",
        )
        score = auth_score(auth)
        assert score == 0.0

    def test_partial_score(self):
        from eti_core.models import AuthResult
        auth = AuthResult(
            spf=AuthStatus.PASS,
            dkim=AuthStatus.PASS,
            dmarc=AuthStatus.NONE,
            raw="mx.google.com; dkim=pass; spf=pass; dmarc=none",
        )
        score = auth_score(auth)
        # SPF(0.3) + DKIM(0.4) = 0.7
        assert score == pytest.approx(0.7)

    def test_no_auth_results_header_is_neutral(self):
        """Sin Authentication-Results (raw=None), el score es neutro >= 0.3, no 0.0"""
        from eti_core.models import AuthResult
        auth = AuthResult()  # raw=None por defecto
        score = auth_score(auth)
        assert score >= 0.3  # no debe castigar como si fuera fail

    def test_no_auth_with_dkim_signature_gives_partial(self):
        """Sin AR pero con DKIM NEUTRAL (de DKIM-Signature header), score es mayor que el mínimo"""
        from eti_core.models import AuthResult
        auth = AuthResult(dkim=AuthStatus.NEUTRAL)  # raw=None
        score = auth_score(auth)
        assert score >= 0.5  # 0.3 base + 0.2 por DKIM neutral

