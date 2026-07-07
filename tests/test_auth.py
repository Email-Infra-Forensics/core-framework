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
        )
        score = auth_score(auth)
        assert score == pytest.approx(1.0)

    def test_all_fail_score(self):
        from eti_core.models import AuthResult
        auth = AuthResult(
            spf=AuthStatus.FAIL,
            dkim=AuthStatus.FAIL,
            dmarc=AuthStatus.FAIL,
        )
        score = auth_score(auth)
        assert score == 0.0

    def test_partial_score(self):
        from eti_core.models import AuthResult
        auth = AuthResult(
            spf=AuthStatus.PASS,
            dkim=AuthStatus.PASS,
            dmarc=AuthStatus.NONE,
        )
        score = auth_score(auth)
        # SPF(0.3) + DKIM(0.4) = 0.7
        assert score == pytest.approx(0.7)
