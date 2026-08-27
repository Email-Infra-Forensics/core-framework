import json
import os
import re
from pathlib import Path
from collections import Counter, defaultdict

from eti_core.msgid.signature import build_signature, OrgSignature

# Mapeo explícito para agrupar marcas que usan dominios dispares
EXPLICIT_GROUPS = {
    "falabella": [
        "falabella.com", "cl.falabella.com", "mail.falabella.com", "experiencia.falabella.com",
        "falabella.cl", "cmr.cl", "notifica.cl.cmrfalabella.com", "cl.cmrfalabella.com",
        "sodimac.cl", "mail.sodimac.com", "cl.sodimac.com"
    ],
    "bancofalabella": ["bancofalabella.cl", "cl.bancofalabella.com", "bancofalabella.com"],
    "mercadolibre": [
        "mercadolibre.cl", "r.mercadolibre.cl", "a.mercadolibre.cl", "mercadolibre.com",
        "info.mercadolibre.cl", "mercadopago.com", "a.mercadopago.com", "r.mercadopago.com"
    ],
    "bancoestado": [
        "bancoestado.cl", "correo.bancoestado.cl", "correobancoestado.cl", "emailbancoestado.cl",
        "microempresas.bancoestado.cl", "regularizacion.bancoestado.cl", "bestado.cl"
    ],
    "bancochile": ["bancochile.cl", "e.bancochile.cl", "comercial.bancochile.cl"],
    "bci": ["bci.cl", "info.bci.cl", "mail.machbank.cl", "somosmach.com", "mail.somosmach.com", "tbci.cl"],
    "santander": ["santander.cl", "risk.santander.cl", "mensajeria.santander.cl"],
    "scotiabank": ["scotiabank.cl", "hola.scotiabank.cl"],
    "itau": ["itau.cl"],
    "coopeuch": ["coopeuch.cl", "transaccionalcoopeuch.com"],
    "tenpo": ["tenpo.cl"],
    "prex": ["prexcard.cl"],
    "khipu": ["khipu.com"],
    "servipag": ["servipag.cl", "servipag.com"],
    "flow": ["flow.cl"],
    "unired": ["pagos.unired.cl", "infounired.pagototal.cl"],
    "provida": ["provida.cl", "inf.provida.cl"],
    "afphabitat": ["afphabitat.cl", "email.afphabitat.cl", "informaciones.afphabitat.cl"],
    "unoafp": ["unoafp.cl"],
    "afpmodelo": ["afpmodelo.cl"],
    "wom": ["wom.cl", "news.wom.cl", "validacion.wom.cl"],
    "movistar": ["movistar.cl", "emailmovistar.cl", "comunicaciones.movistar.cl", "notificaciones.movistar.cl"],
    "claro": ["clarochile.cl", "emailclarochile.cl", "servicio.emailclarochile.cl", "servicios.emailclarochile.cl"],
    "entel": ["entel.cl"],
    "paris": ["paris.cl", "clientes.paris.cl", "mail.paris.cl", "email.paris.cl", "news.paris.cl", "cencosud.cl"],
    "ripley": ["ripley.cl", "mensajetarjetaripley.cl", "mensajeriaripley.cl", "postventa.ripley.cl"],
    "hites": ["hites.com", "marketing.hites.com", "tarjeta.hites.com", "hites.cl"],
    "abcdin": ["abcdin.cl"],
    "dafiti": ["dafiti.cl", "news.email.dafiti.cl", "newsletter.dafiti.cl"],
    "cruzverde": ["cruzverde.cl", "mailcruzverde.cl"],
    "google": ["google.com", "accounts.google.com", "docs.google.com", "gmail.com", "googlemail.com"],
    "microsoft": [
        "microsoft.com", "accountprotection.microsoft.com", "email2.microsoft.com",
        "engage.microsoft.com", "e-mail.microsoft.com", "communication.microsoft.com",
        "hotmail.com", "outlook.com", "live.com"
    ],
    "amazon": ["amazon.com", "bounces.amazon.com", "primevideo.com"],
    "paypal": ["paypal.com", "emails.paypal.com", "intl.paypal.com", "mail.paypal.com", "communications.paypal.com"],
    "spotify": ["spotify.com", "legal.spotify.com", "alerts.spotify.com"],
    "netflix": ["netflix.com", "join.netflix.com", "account.netflix.com", "members.netflix.com"],
    "facebook": ["facebook.com", "facebookmail.com", "id.facebook.com", "support.facebook.com"],
    "instagram": ["instagram.com", "mail.instagram.com", "e.instagram.com"],
    "linkedin": ["linkedin.com", "e.linkedin.com", "em.linkedin.com"],
    "twitter": ["twitter.com", "x.com"],
    "apple": ["apple.com", "id.apple.com", "email.apple.com"],
    "tiktok": ["tiktok.com", "mail.tiktok.com", "service.tiktok.com"],
    "uber": ["uber.com", "email.uber.com"],
    "didi": ["didi.com", "didiglobal.com", "mx.didiglobal.com"],
    "pedidosya": ["pedidosya.com", "em.pedidosya.com"],
    "skyairline": ["skyairline.com", "mailskyplus.skyairline.com"],
    "trello": ["trello.com"],
    "steampowered": ["steampowered.com"],
    "riotgames": ["riotgames.com", "mail.accounts.riotgames.com"],
    "epicgames": ["epicgames.com", "acct.epicgames.com", "accts.epicgames.com"],
    "blizzard": ["blizzard.com", "battle.net"],
    "acepta": ["acepta.com", "paperless.cl"],
    "sii": ["sii.cl", "e.sii.cl"],
    "verisure": ["verisure.cl", "verisure.trytoku.com"],
    "loyal": ["chile.loyal.ink"],
    "happyfox": ["travelclub.happyfox.com"],
    "melsat": ["melsat.cl"],
    "eeccvirtual": ["eeccvirtual.cl"],
    "medallia": ["express.medallia.com"],
    "altmisnews": ["altmisnews.com"],
    "e-com": ["e-com.cl"],
    "buk": ["buk.cl", "mail.buk.cl", "app.buk.cl"],
    "talana": ["talana.com", "mail.talana.com"],
}

# Mapeo de marcas conocidas a sus palabras clave asociadas (keywords) y sus dominios válidos
BRAND_SIGNATURES = {
    "falabella": {
        "name": "Falabella / CMR",
        "keywords": [
            "falabella", "cmr", "cmr puntos", "puntos cmr", "banco falabella",
            "sodimac", "tottus", "fazil", "linio"
        ],
        "valid_domains": [
            "falabella.com", "falabella.cl", "cmr.cl", "bancofalabella.cl",
            "sodimac.cl", "sodimac.com", "tottus.cl", "tottus.com",
            "notifica.cl.cmrfalabella.com", "cl.cmrfalabella.com",
            "mail.falabella.com", "experiencia.falabella.com", "cl.falabella.com",
            "promociones.falabella.cl", "bancofalabella.com", "cl.bancofalabella.com"
        ]
    },
    "bancochile": {
        "name": "Banco de Chile",
        "keywords": [
            "banco de chile", "bancochile", "banco chile", "banco edwards", "edwards citi",
            "bch", "mi pago bch", "fan banco de chile", "cuenta fan"
        ],
        "valid_domains": [
            "bancochile.cl", "e.bancochile.cl", "comercial.bancochile.cl",
            "bancoedwards.cl", "edwards.cl"
        ]
    },
    "bancoestado": {
        "name": "BancoEstado",
        "keywords": [
            "banco estado", "bancoestado", "cuenta rut", "cuentarut", "banco del estado",
            "rutpass", "compraqui"
        ],
        "valid_domains": [
            "bancoestado.cl", "correo.bancoestado.cl", "correobancoestado.cl",
            "emailbancoestado.cl", "microempresas.bancoestado.cl", "regularizacion.bancoestado.cl",
            "bestado.cl"
        ]
    },
    "santander": {
        "name": "Banco Santander",
        "keywords": [
            "santander", "banco santander", "santander chile", "supergiro", "superpuntos"
        ],
        "valid_domains": [
            "santander.cl", "risk.santander.cl", "mensajeria.santander.cl", "santanderconsumer.cl"
        ]
    },
    "bci": {
        "name": "BCI / MACH",
        "keywords": [
            "bci", "banco bci", "banco de credito e inversiones", "mach", "tarjeta mach",
            "somos mach", "bci corredores"
        ],
        "valid_domains": [
            "bci.cl", "info.bci.cl", "mail.machbank.cl", "somosmach.com", "mail.somosmach.com", "tbci.cl"
        ]
    },
    "scotiabank": {
        "name": "Scotiabank",
        "keywords": ["scotiabank", "scotia", "banco scotiabank"],
        "valid_domains": ["scotiabank.cl", "hola.scotiabank.cl"]
    },
    "itau": {
        "name": "Itaú",
        "keywords": ["itau", "itaú", "banco itau", "banco itaú"],
        "valid_domains": ["itau.cl", "itaú.cl"]
    },
    "mercadolibre": {
        "name": "Mercado Libre / Mercado Pago",
        "keywords": [
            "mercado libre", "mercadolibre", "mercado pago", "mercadopago", "mercado envios", "mercadocredito"
        ],
        "valid_domains": [
            "mercadolibre.cl", "r.mercadolibre.cl", "a.mercadolibre.cl", "mercadolibre.com",
            "info.mercadolibre.cl", "mercadopago.com", "a.mercadopago.com", "r.mercadopago.com",
            "mercadopago.cl"
        ]
    },
    "ripley": {
        "name": "Ripley / Banco Ripley",
        "keywords": ["ripley", "banco ripley", "tarjeta ripley", "ripley puntos"],
        "valid_domains": ["ripley.cl", "mensajetarjetaripley.cl", "mensajeriaripley.cl", "postventa.ripley.cl", "bancoripley.cl"]
    },
    "paris": {
        "name": "Paris / Cencosud",
        "keywords": ["paris", "tiendas paris", "cencosud", "puntos cencosud", "tarjeta cencosud", "jumbo", "santa isabel"],
        "valid_domains": ["paris.cl", "clientes.paris.cl", "mail.paris.cl", "email.paris.cl", "news.paris.cl", "cencosud.cl", "jumbo.cl", "santaisabel.cl"]
    },
    "sii": {
        "name": "Servicio de Impuestos Internos (SII)",
        "keywords": ["sii", "impuestos internos", "servicio de impuestos", "declaracion de renta", "factura electronica sii"],
        "valid_domains": ["sii.cl", "e.sii.cl", "notificaciones.sii.cl"]
    },
    "tenpo": {
        "name": "Tenpo",
        "keywords": ["tenpo", "tarjeta tenpo", "cuenta tenpo"],
        "valid_domains": ["tenpo.cl"]
    },
    "servipag": {
        "name": "Servipag",
        "keywords": ["servipag", "cuenta servipag", "pago servipag"],
        "valid_domains": ["servipag.cl", "servipag.com"]
    },
    "coopeuch": {
        "name": "Coopeuch",
        "keywords": ["coopeuch", "cooperativa coopeuch", "credito coopeuch"],
        "valid_domains": ["coopeuch.cl", "transaccionalcoopeuch.com"]
    },
    "entel": {
        "name": "Entel",
        "keywords": ["entel", "entel pcs", "entel fibra", "mi entel"],
        "valid_domains": ["entel.cl"]
    },
    "movistar": {
        "name": "Movistar",
        "keywords": ["movistar", "telefonica", "movistar play", "mi movistar"],
        "valid_domains": ["movistar.cl", "emailmovistar.cl", "comunicaciones.movistar.cl", "notificaciones.movistar.cl"]
    },
    "wom": {
        "name": "WOM",
        "keywords": ["wom", "wom chile", "prepago wom", "postpago wom"],
        "valid_domains": ["wom.cl", "news.wom.cl", "validacion.wom.cl"]
    },
    "claro": {
        "name": "Claro",
        "keywords": ["claro", "claro chile", "mi claro", "clarochile"],
        "valid_domains": ["clarochile.cl", "emailclarochile.cl", "servicio.emailclarochile.cl", "servicios.emailclarochile.cl"]
    },
    "afphabitat": {
        "name": "AFP Habitat",
        "keywords": ["afp habitat", "habitat afp", "afphabitat", "fondo mutuo habitat"],
        "valid_domains": ["afphabitat.cl", "email.afphabitat.cl", "informaciones.afphabitat.cl"]
    },
    "provida": {
        "name": "AFP ProVida",
        "keywords": ["provida", "afp provida", "afpprovida"],
        "valid_domains": ["provida.cl", "inf.provida.cl"]
    },
    "unoafp": {
        "name": "AFP Uno",
        "keywords": ["uno afp", "afp uno", "unoafp"],
        "valid_domains": ["unoafp.cl"]
    },
    "paypal": {
        "name": "PayPal",
        "keywords": ["paypal", "pago paypal", "cuenta paypal"],
        "valid_domains": ["paypal.com", "emails.paypal.com", "intl.paypal.com", "mail.paypal.com", "communications.paypal.com"]
    },
    "netflix": {
        "name": "Netflix",
        "keywords": ["netflix", "cuenta netflix", "suscripcion netflix"],
        "valid_domains": ["netflix.com", "join.netflix.com", "account.netflix.com", "members.netflix.com"]
    },
    "google": {
        "name": "Google",
        "keywords": ["google security", "alerta de seguridad google", "cuenta de google", "google workspace"],
        "valid_domains": ["google.com", "accounts.google.com", "docs.google.com", "notifications.google.com"]
    },
    "microsoft": {
        "name": "Microsoft",
        "keywords": ["microsoft security", "alerta de seguridad microsoft", "cuenta microsoft", "office 365", "microsoft 365"],
        "valid_domains": ["microsoft.com", "accountprotection.microsoft.com", "email2.microsoft.com", "engage.microsoft.com", "e-mail.microsoft.com", "communication.microsoft.com"]
    }
}

# Compatibilidad hacia atrás
KNOWN_BRAND_NAMES = [kw for info in BRAND_SIGNATURES.values() for kw in info["keywords"]]


def check_spoofing_attempt(
    from_header: str,
    subject: str = "",
    body_snippet: str = "",
    sender_domain: str = "",
) -> tuple[bool, str | None, str | None]:
    """
    Detecta si un correo pretende ser de una marca conocida (banco, retail, etc.)
    pero el remitente real NO pertenece a los dominios oficiales de esa marca.

    Returns:
        tuple (is_spoofing, brand_name, reason_message)
    """
    if not sender_domain:
        return False, None, None

    sender_domain_lower = sender_domain.lower().strip()

    # 1. Si el remitente es un dominio oficial autorizado de alguna marca protegida
    # (ej: bancochile.cl enviando un comprobante de transferencia donde menciona bancoestado),
    # NO es suplantación externa; es una entidad bancaria/retail oficial comunicándose.
    is_corporate_brand = False
    for brand_key, brand_info in BRAND_SIGNATURES.items():
        valid_domains = [d.lower() for d in brand_info["valid_domains"]]
        if any(sender_domain_lower == d or sender_domain_lower.endswith("." + d) for d in valid_domains):
            is_corporate_brand = True
            break

    if is_corporate_brand:
        return False, None, None

    # 2. Si el remitente NO es una entidad oficial (ej: Gmail, UDP, VPS atacante, etc.),
    # revisar si el Display Name, Asunto o cuerpo pretenden ser una marca protegida
    from_display_match = re.search(r'^"?([^"<]+)"?\s*<', from_header or "")
    display_name = from_display_match.group(1).strip().lower() if from_display_match else ""

    inspect_text = f"{display_name} {subject or ''} {body_snippet or ''}".lower()

    for brand_key, brand_info in BRAND_SIGNATURES.items():
        for kw in brand_info["keywords"]:
            pattern = rf"\b{re.escape(kw)}\b"
            if re.search(pattern, inspect_text, re.IGNORECASE):
                # ¡SUPLANTACIÓN DETECTADA!
                brand_name = brand_info["name"]
                reason = (
                    f"[SUPLANTACIÓN] El mensaje alude a '{brand_name}' (detectado '{kw}'), "
                    f"pero el remitente real '@{sender_domain_lower}' no pertenece a los dominios autorizados de la entidad."
                )
                return True, brand_name, reason

    return False, None, None


def get_org_for_domain(domain: str) -> str:
    """Clasifica un dominio en su organización paraguas, o infiere el nombre base."""
    if not domain:
        return "unknown"
    domain_lower = domain.lower().strip()
    # Buscar en grupos explícitos
    for org, domains in EXPLICIT_GROUPS.items():
        if domain_lower in domains or any(domain_lower.endswith("." + d) for d in domains):
            return org

    # Si no está, deducir la org a partir del second level domain
    # Ejemplo: mail.cruzverde.cl -> cruzverde
    parts = domain_lower.split('.')
    if len(parts) >= 2:
        # casos .com.ar, .com.br, etc.
        if parts[-2] in ('com', 'co', 'gob', 'gov', 'net', 'org', 'mil') and len(parts) > 2:
            return parts[-3]
        return parts[-2]
    return domain_lower

def main():
    jsonl_path = Path("/home/luval/Escritorio/Email-Trust/data-curator/data/out.jsonl")
    if not jsonl_path.exists():
        print(f"Error: No se encontro {jsonl_path}")
        return

    # Estructuras
    org_msgids = defaultdict(list)
    org_ips = defaultdict(list)
    org_auth = defaultdict(list)
    
    print("Analizando y categorizando dominios masivamente...")
    
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                data = json.loads(line)
                domain = data.get("sender_domain", "")
                if not domain:
                    continue
                    
                org = get_org_for_domain(domain)
                
                # Message ID
                msgid = data.get("message_id_raw")
                if msgid:
                    org_msgids[org].append(msgid)
                    
                # IPs
                for hop in data.get("received_hops", []):
                    ip = hop.get("ip")
                    if ip:
                        org_ips[org].append(ip)
                        
                # Auth
                auth_raw = data.get("authentication_results_raw", "") or ""
                auth_summary = []
                auth_raw_lower = auth_raw.lower()
                if "dkim=pass" in auth_raw_lower: auth_summary.append("dkim=pass")
                if "spf=pass" in auth_raw_lower: auth_summary.append("spf=pass")
                if "dmarc=pass" in auth_raw_lower: auth_summary.append("dmarc=pass")
                if auth_summary:
                    org_auth[org].append(",".join(auth_summary))
                    
            except json.JSONDecodeError:
                continue

    baselines_dir = Path("/home/luval/Escritorio/Email-Trust/core-framework/data/baselines")
    baselines_dir.mkdir(parents=True, exist_ok=True)
    
    processed_count = 0
    total_samples = 0
    
    print("\n" + "="*50)
    print(" INFORME DE EXTRACCION DE LINEAS BASE (ETI)")
    print("="*50)
    
    # Ordenar por volumen
    sorted_orgs = sorted(org_msgids.items(), key=lambda x: len(x[1]), reverse=True)
    
    for org, msgids in sorted_orgs:
        if len(msgids) < 10:
            continue
            
        processed_count += 1
        total_samples += len(msgids)
        print(f"\n[{org.upper()}] - {len(msgids)} muestras consolidadas")
        
        # Guardar Firma
        sig = build_signature(org, msgids)
        sig_path = baselines_dir / f"{org}_signature.json"
        sig.save(sig_path)
        print(f" [+] Firma MSG-ID: {sig_path.name}")
        
        # Red habitual
        ips = org_ips[org]
        top_ips = Counter(ips).most_common(3)
        print(" [+] Top IPs (Traceroute):")
        for ip, c in top_ips:
            print(f"     - {ip} ({c} apariciones)")
            
        # Auth
        auths = org_auth[org]
        top_auth = Counter(auths).most_common(2)
        print(" [+] Perfiles Criptograficos:")
        for a, c in top_auth:
            pct = round((c / len(auths)) * 100, 1) if auths else 0
            print(f"     - {a} ({pct}%)")

    print(f"\nExito: {processed_count} organizaciones generaron perfiles robustos utilizando {total_samples} muestras en total.")

if __name__ == "__main__":
    main()
