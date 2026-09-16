"""Persistencia mínima de engagements en SQLite.

Las colas de eventos SSE viven en memoria (son inherentemente transitorias,
atadas a una conexión de proceso), pero el estado y el informe final de cada
engagement se persisten a disco. Así, un reinicio o crash del servidor no
borra el rastro de qué se lanzó, contra qué alcance y con qué resultado —
algo que un engagement de red team necesita poder auditar.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any

_DB_PATH_ENV = "REDTEAMCREW_DB"
_DEFAULT_DB_PATH = "outputs/engagements.db"


def _db_path() -> Path:
    return Path(os.getenv(_DB_PATH_ENV, _DEFAULT_DB_PATH))


def _connect() -> sqlite3.Connection:
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS engagements (
            id TEXT PRIMARY KEY,
            inputs TEXT NOT NULL,
            status TEXT NOT NULL,
            error TEXT,
            informe_md TEXT,
            informe_html TEXT,
            informe_json TEXT,
            tactical_summary TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    # Migración de seguridad: añadir columna si no existe (SQLite no soporta ADD COLUMN IF NOT EXISTS)
    try:
        conn.execute("ALTER TABLE engagements ADD COLUMN tactical_summary TEXT")
    except sqlite3.OperationalError:
        pass # La columna ya existe

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id TEXT NOT NULL,
            host TEXT NOT NULL,
            ip TEXT,
            puertos_json TEXT NOT NULL DEFAULT '[]',
            descubierto_via TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id TEXT NOT NULL,
            host TEXT,
            herramienta TEXT NOT NULL,
            severidad TEXT NOT NULL,
            titulo TEXT NOT NULL,
            evidencia TEXT NOT NULL DEFAULT '',
            origen TEXT NOT NULL CHECK (origen IN ('herramienta', 'modelo')),
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    conn.execute("DROP TABLE IF EXISTS network_graph")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS network_graph (
            engagement_id TEXT PRIMARY KEY,
            graph_data TEXT NOT NULL,
            attack_paths TEXT NOT NULL DEFAULT '[]',
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    return conn


def crear(engagement_id: str, inputs: dict[str, Any]) -> None:
    """Registra un engagement nuevo con estado 'running'."""
    with _connect() as conn:
        conn.execute(
            "INSERT INTO engagements (id, inputs, status) VALUES (?, ?, 'running')",
            (engagement_id, json.dumps(inputs, ensure_ascii=False)),
        )


def actualizar(engagement_id: str, **campos: Any) -> None:
    """Actualiza columnas del engagement (status, error, informe_md, informe_html, informe_json, ...)."""
    if not campos:
        return
    set_clause = ", ".join(f"{campo} = ?" for campo in campos)
    with _connect() as conn:
        conn.execute(
            f"UPDATE engagements SET {set_clause} WHERE id = ?",  # noqa: S608 - claves fijas
            (*campos.values(), engagement_id),
        )


def obtener(engagement_id: str) -> dict[str, Any] | None:
    """Devuelve la fila persistida de un engagement, o ``None`` si no existe."""
    with _connect() as conn:
        conn.row_factory = sqlite3.Row
        fila = conn.execute(
            "SELECT * FROM engagements WHERE id = ?", (engagement_id,)
        ).fetchone()
    return dict(fila) if fila else None


def agregar_host(
    engagement_id: str,
    host: str,
    *,
    ip: str = "",
    puertos: list[dict[str, Any]] | None = None,
    descubierto_via: str = "nmap",
) -> None:
    """Registra un host descubierto durante el reconocimiento activo."""
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO hosts (engagement_id, host, ip, puertos_json, descubierto_via)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                engagement_id,
                host,
                ip,
                json.dumps(puertos or [], ensure_ascii=False),
                descubierto_via,
            ),
        )


def listar_hosts(engagement_id: str) -> list[dict[str, Any]]:
    with _connect() as conn:
        conn.row_factory = sqlite3.Row
        filas = conn.execute(
            "SELECT * FROM hosts WHERE engagement_id = ? ORDER BY id", (engagement_id,)
        ).fetchall()
    return [dict(f) for f in filas]


def agregar_hallazgo(  # noqa: PLR0913 - campos propios de un hallazgo, no agrupables sin perder claridad
    engagement_id: str,
    *,
    herramienta: str,
    severidad: str,
    titulo: str,
    origen: str,
    host: str = "",
    evidencia: str = "",
) -> None:
    """Registra un hallazgo. ``origen`` distingue 'herramienta' (verificado por
    ejecución real) de 'modelo' (síntesis/narrativa del LLM) — nunca se mezclan
    bajo la misma etiqueta para preservar la trazabilidad del informe final."""
    if origen not in ("herramienta", "modelo"):
        raise ValueError("origen debe ser 'herramienta' o 'modelo'")
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO findings
                (engagement_id, host, herramienta, severidad, titulo, evidencia, origen)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (engagement_id, host, herramienta, severidad, titulo, evidencia, origen),
        )


def listar_hallazgos(
    engagement_id: str, *, origen: str | None = None
) -> list[dict[str, Any]]:
    with _connect() as conn:
        conn.row_factory = sqlite3.Row
        if origen is not None:
            filas = conn.execute(
                "SELECT * FROM findings WHERE engagement_id = ? AND origen = ? "
                "ORDER BY id",
                (engagement_id, origen),
            ).fetchall()
        else:
            filas = conn.execute(
                "SELECT * FROM findings WHERE engagement_id = ? ORDER BY id",
                (engagement_id,),
            ).fetchall()
    return [dict(f) for f in filas]


def guardar_grafo(engagement_id: str, graph_data: dict[str, Any], attack_paths: list[list[str]]) -> None:
    """Guarda o actualiza la topología del grafo y los caminos de ataque."""
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO network_graph (engagement_id, graph_data, attack_paths, updated_at)
            VALUES (?, ?, ?, datetime('now'))
            ON CONFLICT(engagement_id) DO UPDATE SET
                graph_data = excluded.graph_data,
                attack_paths = excluded.attack_paths,
                updated_at = excluded.updated_at
            """,
            (engagement_id, json.dumps(graph_data, ensure_ascii=False), json.dumps(attack_paths, ensure_ascii=False)),
        )

def obtener_grafo(engagement_id: str) -> dict[str, Any]:
    """Recupera la topología del grafo y caminos de ataque para un engagement."""
    with _connect() as conn:
        fila = conn.execute(
            "SELECT graph_data, attack_paths FROM network_graph WHERE engagement_id = ?", (engagement_id,)
        ).fetchone()
    return {
        "graph": json.loads(fila[0]) if fila else {"nodes": [], "links": []},
        "attack_paths": json.loads(fila[1]) if fila and fila[1] else []
    }

def exportar_hallazgos_json(engagement_id: str) -> str:
    """Exporta todos los hallazgos verificados por herramienta a JSON."""
    hallazgos = listar_hallazgos(engagement_id, origen="herramienta")
    # Limpiar campos de DB que no interesan al consumidor externo
    for h in hallazgos:
        h.pop("id", None)
        h.pop("engagement_id", None)
        h.pop("created_at", None)
    return json.dumps(hallazgos, indent=2, ensure_ascii=False)
