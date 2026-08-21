"""
tests/test_msgid.py — Tests unitarios para el análisis y modelado de Message-ID.
"""

import pytest
from eti_core.msgid.extractor import extract_msgid_components, MessageIDComponents
from eti_core.msgid.provider_rules import detect_provider
from eti_core.msgid.signature import (
    OrgSignature,
    build_signature,
    score_against_signature,
)


def test_detect_provider_google():
    msgid = "<CA+d0zXp9xL1qXyZ8aBcDeFgHiJkLmNoPqRsTuVwXyZ12345678@mail.gmail.com>"
    provider = detect_provider(msgid)
    assert provider == "Google"


def test_detect_provider_microsoft():
    msgid = "<SA0PR15MB412398ABCDEF0123456789ABCDEF@SA0PR15MB4123.namprd15.prod.outlook.com>"
    provider = detect_provider(msgid)
    assert provider == "Microsoft"


def test_detect_provider_amazon_ses():
    msgid = "<0100018b12345678-abcdef01-2345-6789-abcd-ef0123456789-000000@email.amazonses.com>"
    provider = detect_provider(msgid)
    assert provider == "Amazon SES"


def test_extract_msgid_components():
    msgid = "<550e8400-e29b-41d4-a716-446655440000@bancochile.cl>"
    comp = extract_msgid_components(msgid)
    assert comp is not None
    assert comp.domain == "bancochile.cl"
    assert comp.has_uuid is True
    assert comp.local_part_length == 36


def test_build_and_score_signature():
    samples = [
        "<550e8400-e29b-41d4-a716-446655440000@bancochile.cl>",
        "<6ba7b810-9dad-11d1-80b4-00c04fd430c8@bancochile.cl>",
        "<6ba7b811-9dad-11d1-80b4-00c04fd430c8@bancochile.cl>",
        "<6ba7b812-9dad-11d1-80b4-00c04fd430c8@bancochile.cl>",
        "<6ba7b813-9dad-11d1-80b4-00c04fd430c8@bancochile.cl>",
        "<6ba7b814-9dad-11d1-80b4-00c04fd430c8@bancochile.cl>",
    ]
    sig = build_signature("bancochile", samples)
    assert sig.sample_count == 6
    assert sig.uuid_freq == 1.0
    assert "bancochile.cl" in sig.domains

    # Test matching sample
    match_msgid = "<123e4567-e89b-12d3-a456-426614174000@bancochile.cl>"
    score = score_against_signature(match_msgid, sig)
    assert score >= 0.85

    # Test mismatching sample (weird format from unknown domain)
    mismatch_msgid = "<123@phishing-fake.com>"
    score_mismatch = score_against_signature(mismatch_msgid, sig)
    assert score_mismatch < 0.5


def test_signature_serialization(tmp_path):
    sig = OrgSignature(
        org_id="santander",
        sample_count=10,
        uuid_freq=0.0,
        hex_block_freq=1.0,
        domains=["santander.cl"],
    )
    sig_path = tmp_path / "santander.json"
    sig.save(sig_path)

    loaded = OrgSignature.load(sig_path)
    assert loaded.org_id == "santander"
    assert loaded.hex_block_freq == 1.0
    assert loaded.domains == ["santander.cl"]
