"""
enrichment/asn_lookup.py — Mapa de ASNs conocidos a organizaciones/ESPs.

Permite clasificar rápidamente un hop SMTP sin consultar RDAP
para los proveedores más comunes: Google, Amazon SES, Sendgrid, etc.

Este mapa se complementa con la consulta RDAP en rdap_client.py
(que cubre ASNs no conocidos a priori).
"""

from __future__ import annotations

from eti_core.models import HopClassification

# ---------------------------------------------------------------------------
# Mapa de ASN → Organización conocida
# Fuente: https://bgp.he.net, ARIN/LACNIC registries
# Última actualización: julio 2026
# ---------------------------------------------------------------------------

KNOWN_ESP_ASNS: dict[int, str] = {
    # Google / Gmail
    15169: "Google LLC",
    # Microsoft / Outlook / Exchange Online
    8075: "Microsoft Corporation",
    # Amazon / AWS / SES
    16509: "Amazon.com Inc.",
    14618: "Amazon Technologies Inc.",
    # Sendgrid / Twilio
    11377: "Twilio SendGrid",
    # Mailchimp / Mandrill
    393674: "Rocket Science Group (Mailchimp)",
    # Yahoo / Oath
    36646: "Yahoo Inc.",
    10310: "Yahoo Inc.",
    # Fastmail
    24149: "Fastly Inc.",
    # Mailgun (Sinch)
    36483: "Sinch Mailgun",
    # Salesforce / Exacttarget
    49836: "Salesforce Inc.",
    # SparkPost
    40285: "SparkPost / MessageSystems",
    # Proofpoint
    26211: "Proofpoint Inc.",
    # Mimecast
    393540: "Mimecast Services Ltd.",
    # Cloudflare
    13335: "Cloudflare Inc.",
}

# Rangos de IP conocidos por ESP (CIDR → nombre)
# Útil cuando no tenemos el ASN pero sí la IP
KNOWN_ESP_PREFIXES: dict[str, str] = {
    # Google
    "209.85.": "Google Gmail",
    "74.125.": "Google Gmail",
    "64.233.": "Google Gmail",
    "142.250.": "Google",
    # Microsoft
    "40.92.": "Microsoft Exchange Online",
    "40.107.": "Microsoft Exchange Online",
    "52.100.": "Microsoft Exchange Online",
    # Amazon SES
    "199.255.192.": "Amazon SES",
    "54.240.": "Amazon SES",
    "23.251.": "Amazon SES",
    # Sendgrid
    "167.89.": "Sendgrid",
    "198.37.": "Sendgrid",
    # Yahoo
    "98.137.": "Yahoo Mail",
    "66.196.": "Yahoo Mail",
}


def classify_asn(asn: int | None, ip: str | None = None) -> tuple[HopClassification, str | None]:
    """
    Clasifica un hop según su ASN (y opcionalmente su IP como fallback).

    Args:
        asn: Número de sistema autónomo (puede ser None si no se pudo resolver).
        ip: IP del hop (opcional, para fallback por prefijo).

    Returns:
        Tuple (HopClassification, org_name o None)
    """
    # Primero intentar por ASN
    if asn is not None:
        org = KNOWN_ESP_ASNS.get(asn)
        if org:
            return HopClassification.KNOWN_ESP, org

    # Fallback: buscar por prefijo IP
    if ip:
        for prefix, org in KNOWN_ESP_PREFIXES.items():
            if ip.startswith(prefix):
                return HopClassification.KNOWN_ESP, org

    # No identificado
    return HopClassification.UNKNOWN, None


def get_esp_name(asn: int | None, ip: str | None = None) -> str | None:
    """Devuelve el nombre del ESP o None si es desconocido."""
    _, name = classify_asn(asn, ip)
    return name
