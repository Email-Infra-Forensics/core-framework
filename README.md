# eti-core — Email Trust Index Core Framework

Framework forense Python para caracterización de infraestructura de correo electrónico.

## Instalación (con uv)

```bash
# Instalar uv si no lo tienes
curl -LsSf https://astral.sh/uv/install.sh | sh

# Instalar el proyecto en modo desarrollo
cd core-framework
uv sync --extra dev
```

## Uso — CLI

```bash
# Analizar un archivo .eml
uv run eti analyze correo.eml

# Con output JSON
uv run eti analyze correo.eml --json

# Sin enriquecimiento RDAP (más rápido)
uv run eti analyze correo.eml --no-enrich

# Ver estadísticas del cache RDAP
uv run eti cache-stats
```

## Uso — API (FastAPI)

```bash
# Iniciar el servidor
uv run uvicorn eti_core.api:app --reload --port 8000

# Docs en: http://localhost:8000/docs
```

```bash
# Ejemplo de llamada
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "headers": {
      "message-id": "<abc@example.com>",
      "from": "user@example.com",
      "received": ["from smtp.example.com by mx.google.com; Mon, 1 Jan 2024 12:00:00 +0000"],
      "authentication-results": "mx.google.com; dkim=pass; spf=pass; dmarc=pass"
    }
  }'
```

## Tests

```bash
uv run pytest tests/ -v
uv run pytest tests/ -v --cov=eti_core --cov-report=term-missing
```

## Estructura

```
src/eti_core/
├── models.py          # Contratos de datos (Hop, EmailHeaders, TrustScore)
├── traceroute/        # Parser de Received: + detección de anomalías
├── enrichment/        # RDAP/WHOIS + cache SQLite + ASN lookup
├── auth/              # Parser Authentication-Results (SPF/DKIM/DMARC)
├── msgid/             # Extractor + firma por organización
├── scoring/           # Algoritmo ETI (suma ponderada configurable)
├── cli.py             # CLI Typer: `eti analyze`
└── api.py             # FastAPI: POST /analyze
```

## Configuración de pesos (weights.yaml)

Los pesos del algoritmo ETI son editables en `weights.yaml` sin tocar código:

```yaml
weights:
  asn_consistency: 0.40   # Infraestructura de red
  msgid_match: 0.30       # Message-ID vs firma de organización
  auth_validity: 0.30     # SPF/DKIM/DMARC
```

## Dependencias

- `pydantic` — Validación de datos
- `typer` + `rich` — CLI
- `fastapi` + `uvicorn` — API
- `ipwhois` — RDAP/WHOIS
- `pyyaml` — Configuración de pesos
