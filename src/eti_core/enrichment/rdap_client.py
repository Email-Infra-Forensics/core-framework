"""
enrichment/rdap_client.py — Cliente RDAP/WHOIS con retry y cache local.

Resuelve IP → ASN + organización usando ipwhois (RDAP preferido sobre WHOIS).
Incluye:
  - Retry exponencial ante errores de red/rate-limit
  - Cache SQLite local (RDAPCache) para no repetir consultas
  - Clasificación automática de hops según ASN conocido

Uso:
    from eti_core.enrichment.rdap_client import enrich_hops
    hops = enrich_hops(hops)
"""

from __future__ import annotations

import time
from typing import Optional

from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError

from eti_core.enrichment.asn_lookup import classify_asn
from eti_core.enrichment.cache import RDAPCache
from eti_core.models import Hop, HopClassification


# IPs privadas / loopback — no consultar RDAP
_PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
    "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.", "127.", "::1", "fe80:", "fc00:", "fd",
)


def _is_private(ip: str) -> bool:
    """Devuelve True si la IP es privada o de loopback."""
    return any(ip.startswith(prefix) for prefix in _PRIVATE_PREFIXES)


def lookup_ip(
    ip: str,
    cache: Optional[RDAPCache] = None,
    max_retries: int = 3,
    retry_delay: float = 2.0,
) -> dict:
    """
    Resuelve una IP vía RDAP (con fallback a WHOIS legacy).
    Usa cache si se provee.

    Args:
        ip: Dirección IP a resolver.
        cache: Instancia de RDAPCache (opcional).
        max_retries: Intentos máximos ante errores de red.
        retry_delay: Segundos entre reintentos (se duplica con backoff).

    Returns:
        Dict con: asn (int), asn_org (str), asn_description (str),
                  network_name (str), country (str), raw_source (str).
    """
    # Verificar cache primero
    if cache:
        cached = cache.get(ip)
        if cached:
            return cached

    # No consultar IPs privadas
    if _is_private(ip):
        result = {
            "asn": None,
            "asn_org": "Private/RFC1918",
            "asn_description": "Private address space",
            "network_name": "Private",
            "country": None,
            "raw_source": "local",
        }
        if cache:
            cache.set(ip, result)
        return result

    delay = retry_delay
    last_error = None

    for attempt in range(max_retries):
        try:
            obj = IPWhois(ip)
            # Intentar RDAP primero (más estructurado y sin rate-limit tan estricto)
            try:
                rdap = obj.lookup_rdap(depth=1)
                asn = int(rdap.get("asn", 0)) if rdap.get("asn") else None
                result = {
                    "asn": asn,
                    "asn_org": rdap.get("asn_description", ""),
                    "asn_description": rdap.get("asn_description", ""),
                    "network_name": rdap.get("network", {}).get("name", ""),
                    "country": rdap.get("asn_country_code", ""),
                    "raw_source": "rdap",
                }
            except Exception:
                # Fallback a WHOIS legacy
                whois = obj.lookup_whois()
                asn = int(whois.get("asn", 0)) if whois.get("asn") else None
                result = {
                    "asn": asn,
                    "asn_org": whois.get("asn_description", ""),
                    "asn_description": whois.get("asn_description", ""),
                    "network_name": whois.get("nets", [{}])[0].get("name", "") if whois.get("nets") else "",
                    "country": whois.get("asn_country_code", ""),
                    "raw_source": "whois",
                }

            if cache:
                cache.set(ip, result)
            return result

        except IPDefinedError:
            # IP interna / reservada
            result = {
                "asn": None,
                "asn_org": "Reserved/Special",
                "asn_description": "Reserved IP range",
                "network_name": "Reserved",
                "country": None,
                "raw_source": "local",
            }
            if cache:
                cache.set(ip, result)
            return result

        except Exception as e:
            last_error = e
            if attempt < max_retries - 1:
                time.sleep(delay)
                delay *= 2  # backoff exponencial
            continue

    # Todos los intentos fallaron
    return {
        "asn": None,
        "asn_org": f"lookup_failed: {last_error}",
        "asn_description": "",
        "network_name": "",
        "country": None,
        "raw_source": "error",
    }


def enrich_hop(
    hop: Hop,
    cache: Optional[RDAPCache] = None,
    max_retries: int = 3,
) -> Hop:
    """
    Enriquece un Hop con datos ASN/organización de su IP.
    Modifica el hop in-place y lo devuelve.
    """
    if not hop.ip:
        return hop

    data = lookup_ip(hop.ip, cache=cache, max_retries=max_retries)

    hop.asn = data.get("asn")
    hop.asn_org = data.get("asn_org", "")

    # Clasificar según ASN conocido
    classification, _ = classify_asn(hop.asn, hop.ip)
    if hop.classification == HopClassification.UNKNOWN:
        # Solo actualizar si no fue marcado ya como ANOMALOUS
        hop.classification = classification

    return hop


def enrich_hops(
    hops: list[Hop],
    cache: Optional[RDAPCache] = None,
    rate_limit_delay: float = 0.5,
) -> list[Hop]:
    """
    Enriquece todos los hops de una ruta SMTP.

    Args:
        hops: Lista de Hop a enriquecer.
        cache: Cache compartido (se crea uno temporal si no se provee).
        rate_limit_delay: Segundos de espera entre consultas RDAP.

    Returns:
        Lista de Hop enriquecidos.
    """
    _cache = cache or RDAPCache()

    seen_ips: set[str] = set()
    for hop in hops:
        if hop.ip and hop.ip not in seen_ips:
            enrich_hop(hop, cache=_cache)
            seen_ips.add(hop.ip)
            # Rate limiting básico entre consultas
            if not _is_private(hop.ip):
                time.sleep(rate_limit_delay)
        elif hop.ip in seen_ips:
            # Reutilizar datos de una IP ya vista
            data = lookup_ip(hop.ip, cache=_cache)
            hop.asn = data.get("asn")
            hop.asn_org = data.get("asn_org", "")
            classification, _ = classify_asn(hop.asn, hop.ip)
            if hop.classification == HopClassification.UNKNOWN:
                hop.classification = classification

    if cache is None:
        _cache.close()

    return hops
