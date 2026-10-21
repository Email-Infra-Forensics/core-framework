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
    14340: "Salesforce / ExactTarget",
    # SparkPost
    40285: "SparkPost / MessageSystems",
    # Proofpoint
    26211: "Proofpoint Inc.",
    # Mimecast
    393540: "Mimecast Services Ltd.",
    # Cloudflare
    13335: "Cloudflare Inc.",

    # -----------------------------------------------------------------------
    # Redes e Infraestructuras Chilenas (Banca / Telcos / ISPs)
    # -----------------------------------------------------------------------
    # Telcos / Tránsito nacional
    27651: "Entel Chile S.A.",
    7418: "Telefónica Chile / Movistar",
    27947: "Claro Chile S.A.",
    14259: "VTR Comunicaciones",
    6428: "GTD Teleductos S.A.",
    27843: "Mundo Pacífico",

    # Infraestructura Bancaria Nacional
    28666: "Banco de Chile",
    27757: "Banco Santander Chile",
    28099: "Banco del Estado de Chile",
    28571: "Banco de Crédito e Inversiones (BCI)",
    28122: "Banco Itaú Chile",
    28014: "Banco Falabella",
}

# Rangos de IP conocidos por ESP (CIDR → nombre)
# Útil cuando no tenemos el ASN pero sí la IP
KNOWN_ESP_PREFIXES: dict[str, str] = {
    # Google
    "209.85.": "Google Gmail",
    "74.125.": "Google Gmail",
    "64.233.": "Google Gmail",
    "142.250.": "Google",
    "172.217.": "Google",
    # Microsoft
    "40.92.": "Microsoft Exchange Online",
    "40.107.": "Microsoft Exchange Online",
    "52.100.": "Microsoft Exchange Online",
    "52.101.": "Microsoft Exchange Online",
    "104.47.": "Microsoft Exchange Online",
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

    # -----------------------------------------------------------------------
    # Redes chilenas — Banca
    # -----------------------------------------------------------------------
    "200.27.": "BancoEstado Chile",       # LACNIC AS28099
    "190.98.": "Banco de Chile",          # LACNIC AS28666
    "200.45.": "Banco Santander Chile",   # LACNIC AS27757
    "200.54.": "BCI",                     # LACNIC AS28571
    "200.19.": "Banco Itaú Chile",        # LACNIC AS28122
    "190.162.": "Banco Falabella Chile",  # LACNIC AS28014
    "200.111.": "Claro Chile / NTC",      # LACNIC AS27947

    # -----------------------------------------------------------------------
    # Telcos / ISPs chilenos
    # -----------------------------------------------------------------------
    "200.75.": "Entel Chile",             # LACNIC AS27651
    "190.61.": "Entel Chile",
    "200.104.": "Telefónica / Movistar",  # LACNIC AS7418
    "190.96.": "Movistar Chile",
    "200.89.": "VTR Comunicaciones",      # LACNIC AS14259
    "190.160.": "WOM S.A.",
    "200.68.": "GTD Teleductos",          # LACNIC AS6428

    # -----------------------------------------------------------------------
    # ESPs internacionales usados por entidades chilenas
    # -----------------------------------------------------------------------
    "149.72.": "Twilio SendGrid",
    "50.31.": "Twilio SendGrid",
    "108.168.": "Rackspace / MailTrust",
    "198.2.": "Constant Contact",
    "205.201.": "Return Path / Validity",
}



def classify_asn(asn: int | None, ip: str | None = None, host: str | None = None) -> tuple[HopClassification, str | None]:
    """
    Clasifica un hop según su ASN (y opcionalmente su IP o Hostname como fallback).

    Args:
        asn: Número de sistema autónomo (puede ser None si no se pudo resolver).
        ip: IP del hop (opcional, para fallback por prefijo o IP privada).
        host: Hostname o cadena from/by del salto.

    Returns:
        Tuple (HopClassification, org_name o None)
    """
    # 1. Intentar por ASN
    if asn is not None:
        org = KNOWN_ESP_ASNS.get(asn)
        if org:
            return HopClassification.KNOWN_ESP, org

    # 2. Fallback: buscar por prefijo IP
    if ip:
        for prefix, org in KNOWN_ESP_PREFIXES.items():
            if ip.startswith(prefix):
                return HopClassification.KNOWN_ESP, org

        # 3. Verificar si es IP privada (RFC 1918) o loopback
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback:
                return HopClassification.TRANSIT, "Internal Network (RFC 1918)"
        except ValueError:
            pass

    # 4. Fallback por nombre de host
    if host:
        host_lower = host.lower()
        if "google" in host_lower or "gmail" in host_lower or "1e100.net" in host_lower:
            return HopClassification.KNOWN_ESP, "Google LLC"
        if "outlook" in host_lower or "microsoft" in host_lower or "office365" in host_lower:
            return HopClassification.KNOWN_ESP, "Microsoft Corporation"
        if "sendgrid" in host_lower:
            return HopClassification.KNOWN_ESP, "Twilio SendGrid"
        if "amazonses" in host_lower or "awstrack" in host_lower:
            return HopClassification.KNOWN_ESP, "Amazon SES"
        if "exacttarget" in host_lower or "salesforce" in host_lower or ".xt.local" in host_lower:
            return HopClassification.KNOWN_ESP, "Salesforce Marketing Cloud"
        if "bci.cl" in host_lower or "isc.cl" in host_lower or "iport2" in host_lower:
            return HopClassification.KNOWN_ESP, "Banco de Crédito e Inversiones (BCI)"
        if "bancochile.cl" in host_lower:
            return HopClassification.KNOWN_ESP, "Banco de Chile"
        if "bancoestado.cl" in host_lower or "bestado.cl" in host_lower:
            return HopClassification.KNOWN_ESP, "BancoEstado"
        if "santander.cl" in host_lower:
            return HopClassification.KNOWN_ESP, "Banco Santander"

    # No identificado
    return HopClassification.UNKNOWN, None


def get_esp_name(asn: int | None, ip: str | None = None, host: str | None = None) -> str | None:
    """Devuelve el nombre del ESP o None si es desconocido."""
    _, name = classify_asn(asn, ip, host=host)
    return name
