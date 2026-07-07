"""
enrichment/cache.py — Cache SQLite local para RDAP/WHOIS.

Evita golpear rate-limits de servicios RDAP/WHOIS públicos.
TTL configurable (default: 7 días).
Almacenado en ~/.eti_cache/rdap.db (no en el repo).
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional

# Directorio de cache fuera del repo
_DEFAULT_CACHE_DIR = Path.home() / ".eti_cache"
_DEFAULT_TTL_SECONDS = 7 * 24 * 3600  # 7 días


class RDAPCache:
    """Cache SQLite para resultados de RDAP/WHOIS por IP."""

    def __init__(
        self,
        cache_dir: Path = _DEFAULT_CACHE_DIR,
        ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    ) -> None:
        cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = cache_dir / "rdap.db"
        self.ttl = ttl_seconds
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._init_db()

    def _init_db(self) -> None:
        """Crea la tabla si no existe."""
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS rdap_cache (
                ip          TEXT PRIMARY KEY,
                data        TEXT NOT NULL,
                fetched_at  INTEGER NOT NULL
            )
        """)
        self._conn.commit()

    def get(self, ip: str) -> Optional[dict]:
        """Devuelve datos cacheados si existen y no expiraron."""
        row = self._conn.execute(
            "SELECT data, fetched_at FROM rdap_cache WHERE ip = ?", (ip,)
        ).fetchone()

        if row is None:
            return None

        data_json, fetched_at = row
        if time.time() - fetched_at > self.ttl:
            # Expirado — lo eliminamos
            self._conn.execute("DELETE FROM rdap_cache WHERE ip = ?", (ip,))
            self._conn.commit()
            return None

        return json.loads(data_json)

    def set(self, ip: str, data: dict) -> None:
        """Almacena o actualiza datos en cache."""
        self._conn.execute(
            """
            INSERT OR REPLACE INTO rdap_cache (ip, data, fetched_at)
            VALUES (?, ?, ?)
            """,
            (ip, json.dumps(data), int(time.time())),
        )
        self._conn.commit()

    def invalidate(self, ip: str) -> None:
        """Elimina una entrada del cache."""
        self._conn.execute("DELETE FROM rdap_cache WHERE ip = ?", (ip,))
        self._conn.commit()

    def stats(self) -> dict:
        """Devuelve estadísticas del cache."""
        total = self._conn.execute("SELECT COUNT(*) FROM rdap_cache").fetchone()[0]
        expired = self._conn.execute(
            "SELECT COUNT(*) FROM rdap_cache WHERE fetched_at < ?",
            (int(time.time()) - self.ttl,),
        ).fetchone()[0]
        return {
            "total_entries": total,
            "expired_entries": expired,
            "valid_entries": total - expired,
            "db_path": str(self.db_path),
        }

    def close(self) -> None:
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
