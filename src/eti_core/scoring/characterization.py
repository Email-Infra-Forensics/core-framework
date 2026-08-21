import json
import os
import re
from pathlib import Path
from collections import Counter, defaultdict

from eti_core.msgid.signature import build_signature, OrgSignature

# Mapeo explicito para agrupar marcas que usan dominios dispares
EXPLICIT_GROUPS = {
    "falabella": ["falabella.com", "cl.falabella.com", "mail.falabella.com", "experiencia.falabella.com", "falabella.cl", "cmr.cl", "notifica.cl.cmrfalabella.com", "cl.cmrfalabella.com", "sodimac.cl", "mail.sodimac.com", "cl.sodimac.com"],
    "bancofalabella": ["bancofalabella.cl", "cl.bancofalabella.com", "bancofalabella.com"],
    "mercadolibre": ["mercadolibre.cl", "r.mercadolibre.cl", "a.mercadolibre.cl", "mercadolibre.com", "info.mercadolibre.cl", "mercadopago.com", "a.mercadopago.com", "r.mercadopago.com"],
    "bancoestado": ["bancoestado.cl", "correo.bancoestado.cl", "correobancoestado.cl", "emailbancoestado.cl", "microempresas.bancoestado.cl"],
    "bancochile": ["bancochile.cl", "e.bancochile.cl", "comercial.bancochile.cl"],
    "bci": ["bci.cl", "info.bci.cl", "mail.machbank.cl", "somosmach.com", "mail.somosmach.com"],
    "wom": ["wom.cl", "news.wom.cl", "validacion.wom.cl"],
    "movistar": ["emailmovistar.cl", "comunicaciones.movistar.cl", "notificaciones.movistar.cl"],
    "servipag": ["servipag.cl", "servipag.com"],
    "paris": ["paris.cl", "clientes.paris.cl", "mail.paris.cl", "email.paris.cl", "news.paris.cl", "cencosud.cl"],
    "ripley": ["mensajetarjetaripley.cl", "mensajeriaripley.cl", "postventa.ripley.cl"],
    "hites": ["hites.com", "marketing.hites.com", "tarjeta.hites.com", "hites.cl"],
    "google": ["google.com", "accounts.google.com"],
    "paypal": ["emails.paypal.com", "intl.paypal.com", "mail.paypal.com"],
    "spotify": ["spotify.com", "legal.spotify.com"],
    "instagram": ["instagram.com", "mail.instagram.com", "e.instagram.com"],
    "facebook": ["facebook.com", "facebookmail.com", "id.facebook.com"],
    "apple": ["apple.com", "id.apple.com", "email.apple.com"],
    "microsoft": ["microsoft.com", "accountprotection.microsoft.com", "email2.microsoft.com", "engage.microsoft.com"],
    "amazon": ["amazon.com", "bounces.amazon.com"],
    "tiktok": ["tiktok.com", "mail.tiktok.com"],
    "uber": ["uber.com", "email.uber.com"],
    "didi": ["didi.com", "didiglobal.com", "mx.didiglobal.com"],
    "pedidosya": ["pedidosya.com", "em.pedidosya.com"]
}

def get_org_for_domain(domain: str) -> str:
    """Clasifica un dominio en su organizacion paraguas, o infiere el nombre base."""
    # Buscar en grupos explicitos
    for org, domains in EXPLICIT_GROUPS.items():
        if domain in domains:
            return org
            
    # Si no esta, deducir la org a partir del second level domain
    # Ejemplo: mail.cruzverde.cl -> cruzverde
    parts = domain.split('.')
    if len(parts) >= 2:
        # casos .com.ar, .com.br, etc.
        if parts[-2] in ('com', 'co', 'gob', 'gov', 'net', 'org', 'mil') and len(parts) > 2:
            return parts[-3]
        return parts[-2]
    return domain

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
        if len(msgids) < 15:
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
