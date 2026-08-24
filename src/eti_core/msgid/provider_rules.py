"""
msgid/provider_rules.py — Reglas heurísticas de Message-ID por proveedor (ESP).

Define los algoritmos de generación criptográfica y formatos de los principales
proveedores de correo para detectar falsificaciones.
"""

import re
from typing import Optional

# 1. Google (Gmail / Workspace / Notifications)
RE_GOOGLE = re.compile(r"^<[a-zA-Z0-9_\-+=\.]{10,120}@((mail\.)?gmail\.com|[a-zA-Z0-9.-]+\.google\.com|google\.com)>$", re.IGNORECASE)

# 2. Microsoft (Office 365 / Exchange Online / Outlook)
RE_MICROSOFT = re.compile(
    r"^<[a-zA-Z0-9_\-+=\.]{10,120}@[a-zA-Z0-9.-]+\.(outlook|microsoft|protection\.outlook)\.com>$",
    re.IGNORECASE
)

# 3. Amazon SES (todas las regiones)
RE_AMAZON_SES = re.compile(
    r"^<[a-zA-Z0-9]{16}-[a-zA-Z0-9-]{36}-000000@([a-zA-Z0-9-]+\.)?amazonses\.com>$",
    re.IGNORECASE
)

# 4. SendGrid
RE_SENDGRID = re.compile(
    r"^<[a-zA-Z0-9_\-+=\.]{10,120}@[a-zA-Z0-9-]+\.(ismtpd\.)?sendgrid\.net>$",
    re.IGNORECASE
)

# 5. Salesforce Marketing Cloud / ExactTarget
RE_EXACTTARGET = re.compile(
    r"^<[a-zA-Z0-9_\-+=\.]{10,120}@[a-zA-Z0-9-]+\.(xt\.local|exacttarget\.com)>$",
    re.IGNORECASE
)

# 6. Fidelizador (ESP masivo en Chile)
RE_FIDELIZADOR = re.compile(
    r"^<[a-zA-Z0-9_\-+=\.]{10,120}@[a-zA-Z0-9-]+\.fidelizador\.(org|com)>$",
    re.IGNORECASE
)

# 7. Mailgun (Sinch)
RE_MAILGUN = re.compile(
    r"^<[a-zA-Z0-9_\-+=\.]{10,120}@[a-zA-Z0-9-]+\.mailgun\.(org|net)>$",
    re.IGNORECASE
)

# 8. Servidores Nativos (Postfix / Exim genérico)
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
    if not raw_msgid:
        return "Unknown"
    raw_msgid = raw_msgid.strip()
    
    if RE_GOOGLE.match(raw_msgid):
        return "Google"
    elif RE_MICROSOFT.match(raw_msgid):
        return "Microsoft"
    elif RE_AMAZON_SES.match(raw_msgid):
        return "Amazon SES"
    elif RE_SENDGRID.match(raw_msgid):
        return "SendGrid"
    elif RE_EXACTTARGET.match(raw_msgid):
        return "Salesforce ExactTarget"
    elif RE_FIDELIZADOR.match(raw_msgid):
        return "Fidelizador"
    elif RE_MAILGUN.match(raw_msgid):
        return "Mailgun"
    elif RE_NATIVE.match(raw_msgid):
        return "Native (Postfix/Exim)"
    
    return "Unknown"
