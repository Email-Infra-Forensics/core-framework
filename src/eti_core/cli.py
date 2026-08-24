"""
cli.py — CLI del framework ETI.

Comandos:
  eti analyze <correo.eml>        → analiza un .eml y muestra ETI
  eti analyze-headers <headers>   → analiza headers en texto plano
  eti cache-stats                 → muestra estadísticas del cache RDAP
  eti version                     → muestra la versión

Uso:
  uv run eti analyze correo.eml
  uv run eti analyze correo.eml --no-enrich   (sin RDAP)
  uv run eti analyze correo.eml --json        (output JSON)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from eti_core import __version__

app = typer.Typer(
    name="eti",
    help="Email Trust Index — Framework forense de infraestructura de correo",
    rich_markup_mode="rich",
)

console = Console()
err_console = Console(stderr=True)


def _print_trust_score(score, verbose: bool = False) -> None:
    """Imprime el TrustScore de forma legible con Rich."""
    from eti_core.models import TrustScore

    color = {
        "trusted": "green",
        "suspicious": "yellow",
        "anomalous": "red",
    }.get(score.label, "white")

    panel = Panel(
        f"[bold {color}]ETI: {score.eti:.1f} / 100[/]\n"
        f"[{color}]Status: {score.label.upper()}[/]\n"
        f"Message-ID: {score.message_id or 'N/A'}\n"
        f"Dominio: {score.sender_domain or 'N/A'}",
        title="[bold]Email Trust Index[/]",
        border_style=color,
    )
    console.print(panel)

    # Tabla de breakdown
    table = Table(title="Breakdown del Score", box=box.SIMPLE, show_header=True)
    table.add_column("Componente", style="bold")
    table.add_column("Score", justify="right")
    table.add_column("Peso", justify="right")

    bd = score.breakdown
    table.add_row("ASN / Infraestructura", f"{bd.asn_consistency:.2f}", "40%")
    table.add_row("Message-ID Match", f"{bd.msgid_match:.2f}", "30%")
    table.add_row("Auth SPF/DKIM/DMARC", f"{bd.auth_validity:.2f}", "30%")
    console.print(table)

    # Estadísticas de hops
    console.print(
        f"\n[dim]Hops: {bd.hop_count} total | "
        f"{bd.anomalous_hops} anómalos | "
        f"{bd.known_esp_hops} ESPs conocidos[/]"
    )

    if verbose and bd.reasons:
        console.print("\n[bold]Razones:[/]")
        for r in bd.reasons:
            bullet_color = "red" if "fail" in r or "anomal" in r else "green"
            console.print(f"  [{bullet_color}]•[/] {r}")


@app.command()
def analyze(
    eml_path: Annotated[Path, typer.Argument(help="Ruta al archivo .eml a analizar")],
    enrich: Annotated[bool, typer.Option("--enrich/--no-enrich", help="Consultar RDAP para enriquecer hops")] = True,
    json_output: Annotated[bool, typer.Option("--json", help="Output en formato JSON")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Mostrar razones detalladas")] = False,
    org: Annotated[Optional[str], typer.Option("--org", help="ID de organización para comparar firma")] = None,
    signatures_dir: Annotated[Optional[Path], typer.Option("--sigs", help="Directorio de firmas de organizaciones")] = None,
) -> None:
    """
    Analiza un archivo .eml y calcula el Email Trust Index.
    """
    if not eml_path.exists():
        err_console.print(f"[red]Error: No se encontró el archivo {eml_path}[/]")
        raise typer.Exit(1)

    if not eml_path.suffix.lower() == ".eml":
        err_console.print(f"[yellow]Advertencia: El archivo no tiene extensión .eml[/]")

    console.print(f"[dim]Analizando: {eml_path}[/]")

    # Imports locales para no ralentizar el inicio del CLI
    from eti_core.traceroute.parser import parse_eml_file
    from eti_core.traceroute.ordering import detect_orphan_hops, sort_hops_by_timestamp
    from eti_core.auth.spf_dkim_dmarc import parse_all_auth_headers
    from eti_core.scoring.eti import calculate_eti
    from eti_core.models import EmailHeaders, AuthResult
    from eti_core.msgid.extractor import extract_domain_from_msgid
    import re
    from datetime import datetime

    try:
        headers_dict, hops = parse_eml_file(eml_path)
    except Exception as e:
        err_console.print(f"[red]Error al parsear {eml_path}: {e}[/]")
        raise typer.Exit(1)

    # Ordenar y detectar anomalías
    hops = sort_hops_by_timestamp(hops)
    hops = detect_orphan_hops(hops)

    # Enriquecer con RDAP si se pide
    if enrich and hops:
        from eti_core.enrichment.rdap_client import enrich_hops
        from eti_core.enrichment.cache import RDAPCache
        with RDAPCache() as cache:
            console.print("[dim]Resolviendo ASNs (RDAP)...[/]")
            hops = enrich_hops(hops, cache=cache)

    # Parsear autenticación
    auth = parse_all_auth_headers(headers_dict)

    # Extraer dominio del remitente
    message_id = headers_dict.get("message-id", "")
    if isinstance(message_id, list):
        message_id = message_id[0]

    from_header = headers_dict.get("from", "")
    if isinstance(from_header, list):
        from_header = from_header[0]
    # Extraer dominio del from
    domain_match = re.search(r"@([\w.\-]+)", from_header or "")
    sender_domain = domain_match.group(1) if domain_match else extract_domain_from_msgid(message_id)

    # Construir EmailHeaders
    email_headers = EmailHeaders(
        message_id=message_id or None,
        from_address=from_header or "unknown",
        to_address=headers_dict.get("to", "unknown") if isinstance(headers_dict.get("to"), str) else "unknown",
        hops=hops,
        auth=auth,
        sender_domain=sender_domain,
        source_file=str(eml_path),
    )

    # Cargar firma de organización si se especificó o por auto-detección
    org_signature = None
    base_dir = Path(__file__).resolve().parent.parent.parent / "data" / "baselines"
    if not base_dir.exists():
        for cand in [
            Path.cwd() / "data" / "baselines",
            Path.cwd() / "core-framework" / "data" / "baselines",
            Path("/home/luval/Escritorio/Email-Trust/core-framework/data/baselines"),
        ]:
            if cand.exists():
                base_dir = cand
                break
    
    sender_in_db = False
    if org and signatures_dir:
        from eti_core.msgid.signature import OrgSignature
        sig_path = signatures_dir / f"{org}.json"
        if not sig_path.exists():
            sig_path = signatures_dir / f"{org}_signature.json"
        if sig_path.exists():
            org_signature = OrgSignature.load(sig_path)
            sender_in_db = True
        else:
            console.print(f"[yellow]Advertencia: No se encontró firma para '{org}' en {signatures_dir}[/]")
    elif sender_domain and base_dir.exists():
        from eti_core.msgid.signature import OrgSignature
        from eti_core.scoring.characterization import get_org_for_domain, EXPLICIT_GROUPS

        sender_domain_lower = sender_domain.lower()
        org_name = get_org_for_domain(sender_domain_lower)

        if org_name and org_name != "unknown":
            sig_candidate = base_dir / f"{org_name}_signature.json"
            if sig_candidate.exists() or org_name in EXPLICIT_GROUPS:
                sender_in_db = True

        if not sender_in_db:
            for pf in base_dir.glob("*_signature.json"):
                org_prefix = pf.name.replace("_signature.json", "")
                if org_prefix in sender_domain_lower:
                    org_name = org_prefix
                    sender_in_db = True
                    break

        if org_name:
            sig_file = base_dir / f"{org_name}_signature.json"
            if sig_file.exists():
                try:
                    org_signature = OrgSignature.load(sig_file)
                except Exception:
                    pass

    # Calcular ETI
    score = calculate_eti(
        email_headers,
        org_signature=org_signature,
        sender_in_db=sender_in_db if sender_domain else False,
    )

    if json_output:
        print(score.model_dump_json(indent=2))
    else:
        _print_trust_score(score, verbose=verbose)


@app.command()
def build_signature(
    samples_file: Annotated[Path, typer.Argument(help="Archivo de texto (.txt) con un Message-ID por línea o JSONL")],
    org_id: Annotated[str, typer.Option("--org", "-o", help="Identificador de la organización (ej: santander, bancoestado)")],
    output: Annotated[Optional[Path], typer.Option("--output", "-out", help="Ruta de salida para el archivo JSON")] = None,
) -> None:
    """
    Construye una firma matemática OrgSignature a partir de una lista de Message-IDs.
    """
    from eti_core.msgid.signature import build_signature as _build_sig
    
    if not samples_file.exists():
        err_console.print(f"[red]Error: No se encontró el archivo {samples_file}[/]")
        sys.exit(1)
        
    samples = []
    lines = samples_file.read_text(encoding="utf-8").splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith("{") and "message_id_raw" in line:
            try:
                data = json.loads(line)
                if data.get("message_id_raw"):
                    samples.append(data["message_id_raw"])
            except Exception:
                pass
        else:
            samples.append(line)
            
    if not samples:
        err_console.print(f"[red]Error: No se encontraron muestras de Message-ID en {samples_file}[/]")
        sys.exit(1)
        
    sig = _build_sig(org_id, samples)
    out_path = output or Path(f"{org_id}_signature.json")
    sig.save(out_path)
    console.print(f"[green]✓ Firma construida exitosamente para '{org_id}' ({sig.sample_count} muestras): {out_path}[/]")


@app.command()
def cache_stats() -> None:
    """Muestra estadísticas del cache RDAP local."""
    from eti_core.enrichment.cache import RDAPCache
    with RDAPCache() as cache:
        stats = cache.stats()

    table = Table(title="Cache RDAP", box=box.SIMPLE)
    table.add_column("Stat", style="bold")
    table.add_column("Valor", justify="right")
    for k, v in stats.items():
        table.add_row(k, str(v))
    console.print(table)


@app.command()
def version() -> None:
    """Muestra la versión del framework."""
    console.print(f"eti-core v{__version__}")


if __name__ == "__main__":
    app()
