"""
msgid/provider_rules.py — Reglas heurísticas de Message-ID por proveedor (ESP).

Define los algoritmos de generación criptográfica y formatos de los principales
proveedores de correo para detectar falsificaciones.
"""

import re
from typing import Optional

# 1. Google (Gmail / Workspace)
# Formato típico: <[alfanumérico aleatorio con + o -]@mail.gmail.com> o @google.com
RE_GOOGLE = re.compile(r"^<[a-zA-Z0-9_\-+=\.]{15,100}@(mail\.)?gmail\.com>$", re.IGNORECASE)

# 2. Microsoft (Office 365 / Exchange Online)
# Formato: <[ID]@[hostname].prod.outlook.com> o <[GUID]@[hostname].outlook.com>
RE_MICROSOFT = re.compile(
    r"^<[a-zA-Z0-9_\-+=\.]{15,100}@[a-zA-Z0-9.-]+\.outlook\.com>$",
    re.IGNORECASE
)

# 3. Amazon SES
# Formato: <[Hash]-[UUID parcial]-[000000]@email.amazonses.com>
RE_AMAZON_SES = re.compile(
    r"^<[a-zA-Z0-9]{16}-[a-zA-Z0-9-]{36}-000000@(email\.)?amazonses\.com>$",
    re.IGNORECASE
)

# 4. SendGrid
# Formato: <[Epoch].[Hash]@[Hostname].ismtpd.sendgrid.net>
RE_SENDGRID = re.compile(
    r"^<1[5-9]\d{8}\.[a-zA-Z0-9]+@[a-zA-Z0-9-]+\.ismtpd\.sendgrid\.net>$",
    re.IGNORECASE
)

# 5. Servidores Nativos (Postfix / Exim genérico)
# Formato: <[YYYYMMDDHHMMSS].[PID].[Aleatorio]@[FQDN]>
RE_NATIVE = re.compile(
    r"^<20\d{12}\.[a-zA-Z0-9]+@[a-zA-Z0-9.-]+>$",
    re.IGNORECASE
)

def detect_provider(raw_msgid: str) -> Optional[str]:
    """
    Intenta identificar el proveedor que generó el Message-ID basándose en
    patrones algorítmicos conocidos de la industria.
    """
    raw_msgid = raw_msgid.strip()
    
    if RE_GOOGLE.match(raw_msgid):
        return "Google"
    elif RE_MICROSOFT.match(raw_msgid):
        return "Microsoft"
    elif RE_AMAZON_SES.match(raw_msgid):
        return "Amazon SES"
    elif RE_SENDGRID.match(raw_msgid):
        return "SendGrid"
    elif RE_NATIVE.match(raw_msgid):
        return "Native (Postfix/Exim)"
    
    return "Unknown"
