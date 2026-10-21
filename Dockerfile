# ==============================================================================
# Dockerfile para Producción: ETI Core Framework (FastAPI)
# ==============================================================================
FROM python:3.12-slim

WORKDIR /app

# Instalar dependencias del sistema necesarias para red y compilación
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copiar archivos de dependencias
COPY pyproject.toml weights.yaml ./
COPY src/ ./src/

# Instalar uv para instalación ultra-rápida y reproducibilidad
RUN pip install --no-cache-dir uv && \
    uv pip install --system --no-cache -e .

# Variables de entorno
ENV PORT=8000
ENV HOST=0.0.0.0
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

# Comando de inicio para producción con Uvicorn
CMD ["uvicorn", "eti_core.api:app", "--host", "0.0.0.0", "--port", "8000"]
