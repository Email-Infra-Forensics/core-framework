"""
tests/test_enrichment.py — Tests para el módulo de enriquecimiento de red y ASN.
"""

import pytest
from eti_core.enrichment.asn_lookup import classify_asn, get_esp_name, KNOWN_ESP_ASNS
from eti_core.enrichment.cache import RDAPCache
from eti_core.models import HopClassification


def test_classify_known_esp_asn():
    classification, org = classify_asn(15169)
    assert classification == HopClassification.KNOWN_ESP
    assert org == "Google LLC"


def test_classify_chilean_asn():
    classification, org = classify_asn(28099)
    assert classification == HopClassification.KNOWN_ESP
    assert org == "Banco del Estado de Chile"

    classification, org = classify_asn(27651)
    assert classification == HopClassification.KNOWN_ESP
    assert org == "Entel Chile S.A."


def test_classify_ip_prefix_fallback():
    classification, org = classify_asn(None, ip="209.85.128.1")
    assert classification == HopClassification.KNOWN_ESP
    assert "Google" in org


def test_classify_unknown_asn():
    classification, org = classify_asn(999999, ip="1.2.3.4")
    assert classification == HopClassification.UNKNOWN
    assert org is None


def test_rdap_cache(tmp_path):
    cache = RDAPCache(cache_dir=tmp_path)

    # Debe retornar None si no está en cache
    assert cache.get("8.8.8.8") is None

    # Guardar en cache
    cache.set(
        "8.8.8.8",
        {
            "asn": 15169,
            "as_name": "GOOGLE",
            "org_name": "Google LLC",
            "country": "US",
            "source": "rdap",
        },
    )

    entry = cache.get("8.8.8.8")
    assert entry is not None
    assert entry["asn"] == 15169
    assert entry["org_name"] == "Google LLC"

    stats = cache.stats()
    assert stats["total_entries"] == 1
