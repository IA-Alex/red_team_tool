"""Servidor HTTP del panel de operaciones Zotz.

Expone el flujo de red team de LangGraph como una API REST + SSE:
- ``POST /api/engagements``                    crea un engagement y lo encola.
- ``POST /api/engagements/{id}/approve``        decide la aprobación humana pendiente.
- ``GET  /api/engagements/{id}/events``         canal SSE con las fases en vivo.
- ``GET  /api/engagements/{id}/informe.md``     informe final en Markdown.
- ``GET  /api/engagements/{id}/informe.html``   informe final en HTML.

Esta API es una capa delgada: no ejecuta el flujo. Encola el trabajo en
``redteamcrew.worker`` vía arq/Redis y retransmite por SSE lo que el worker
publica en un stream de Redis (``engagement:{id}:events``). Todo el estado
persistente (inputs, status, informe, hosts, hallazgos) vive en SQLite
(``api/store.py``), así que este proceso no guarda nada en memoria — se
puede reiniciar sin perder el rastro de ningún engagement.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator

import redis.asyncio as redis_asyncio
from arq import create_pool
from arq.connections import ArqRedis, RedisSettings
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field, field_validator

from redteamcrew.api import store
from redteamcrew.scope import ScopeError, validate_scope
from redteamcrew.utils.logger import get_logger

log = get_logger("api")

_API_KEY_ENV = "REDTEAMCREW_API_KEY"
_TRUST_PROXY_ENV = "REDTEAMCREW_TRUST_PROXY"
_RATE_LIMIT_WINDOW_S = 300.0
_RATE_LIMIT_MAX_PETICIONES = 5
_REDIS_URL_ENV = "REDTEAMCREW_REDIS_URL"
_DEFAULT_REDIS_URL = "redis://localhost:6379"
_SSE_BLOCK_MS = 15000
_SSE_MAX_RECONEXIONES = 10
_SSE_BACKOFF_BASE_S = 0.5
_SSE_BACKOFF_MAX_S = 10.0


def _redis_url() -> str:
    return os.getenv(_REDIS_URL_ENV, _DEFAULT_REDIS_URL)


def _canal(engagement_id: str) -> str:
    return f"engagement:{engagement_id}:events"


def _client_ip(request: Request) -> str:
    """IP del cliente para el rate limit.

    ``request.client.host`` es la IP del socket TCP, que si la API corre tras
    un proxy/load balancer es siempre la del proxy, no la del cliente real —
    todo el tráfico compartiría esa única IP y el límite dejaría de discriminar
    por operador. Solo se confía en ``X-Forwarded-For`` (fácilmente
    falsificable por cualquier cliente que hable directo con el proceso) si el
    operador confirma explícitamente que hay un proxy de confianza delante
    fijando ``REDTEAMCREW_TRUST_PROXY=1``.
    """
    if os.getenv(_TRUST_PROXY_ENV, "0").strip() == "1":
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "desconocido"


@dataclass
class Engagement:
    """Vista de solo lectura de un engagement, reconstruida desde SQLite."""

    id: str
    inputs: dict[str, Any]
    status: str = "running"  # running | esperando_aprobacion | completed | error
    error: str | None = None
    informe_md: str = ""
    informe_html: str = ""
    tactical_summary: str = ""


class EngagementManager:
    """Fachada sobre ``api.store`` — este proceso no guarda estado propio."""

    def create(self, inputs: dict[str, Any]) -> Engagement:
        eng = Engagement(id=uuid.uuid4().hex, inputs=inputs)
        store.crear(eng.id, inputs)
        return eng

    def get(self, engagement_id: str) -> Engagement:
        fila = store.obtener(engagement_id)
        if fila is None:
            raise HTTPException(status_code=404, detail="Engagement no encontrado")
        return Engagement(
            id=fila["id"],
            inputs=json.loads(fila["inputs"]),
            status=fila["status"],
            error=fila["error"],
            informe_md=fila["informe_md"] or "",
            informe_html=fila["informe_html"] or "",
            tactical_summary=fila.get("tactical_summary") or "",
        )


manager = EngagementManager()

app = FastAPI(title="Zotz Red Team API", version="0.1.0")

# Ruta al panel web (frontend). Se sirve el HTML estático en la raíz.
_FRONTEND = Path(__file__).resolve().parents[3] / "frontend_zotz_web_panel.html"

_arq_pool_cache: dict[str, ArqRedis] = {}


async def _obtener_pool() -> ArqRedis:
    """Pool de conexión arq, creado perezosamente y reutilizado entre requests."""
    if "pool" not in _arq_pool_cache:
        settings = RedisSettings.from_dsn(_redis_url())
        _arq_pool_cache["pool"] = await create_pool(settings)
    return _arq_pool_cache["pool"]


async def _encolar(eng: Engagement) -> None:
    pool = await _obtener_pool()
    await pool.enqueue_job("ejecutar_engagement", eng.id)


async def _encolar_resume(engagement_id: str, decision: dict[str, Any]) -> None:
    pool = await _obtener_pool()
    await pool.enqueue_job("reanudar_engagement", engagement_id, decision)


def _verificar_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Exige ``X-API-Key`` si el operador configuró ``REDTEAMCREW_API_KEY``.

    Si la variable no está definida, la autenticación queda deshabilitada
    (solo recomendable para desarrollo local en 127.0.0.1).
    """
    clave = os.getenv(_API_KEY_ENV)
    if not clave:
        return
    # Comparación de tiempo constante: evita filtrar por timing cuántos
    # caracteres iniciales de la clave coinciden.
    if not hmac.compare_digest(x_api_key or "", clave):
        raise HTTPException(status_code=401, detail="API key inválida o ausente")


_RATE_LIMIT_KEY_PREFIX = "ratelimit:engagement:"


async def _verificar_rate_limit(request: Request) -> None:
    """Limita cuántos engagements puede lanzar una misma IP por ventana.

    El límite se lleva en un sorted set de Redis (no en un dict en memoria
    del proceso): con varias réplicas de la API detrás de un balanceador, un
    historial en memoria de proceso solo ve la fracción de peticiones que le
    tocó a esa réplica, así que repartir peticiones entre réplicas evadía el
    límite por completo.
    """
    ip = _client_ip(request)
    clave = f"{_RATE_LIMIT_KEY_PREFIX}{ip}"
    ahora = time.time()
    pool = await _obtener_pool()

    async with pool.pipeline(transaction=True) as pipe:
        pipe.zremrangebyscore(clave, 0, ahora - _RATE_LIMIT_WINDOW_S)
        pipe.zcard(clave)
        _, conteo = await pipe.execute()

    if conteo >= _RATE_LIMIT_MAX_PETICIONES:
        raise HTTPException(
            status_code=429,
            detail="Demasiados engagements lanzados; inténtalo más tarde",
        )

    async with pool.pipeline(transaction=True) as pipe:
        pipe.zadd(clave, {uuid.uuid4().hex: ahora})
        pipe.expire(clave, int(_RATE_LIMIT_WINDOW_S))
        await pipe.execute()


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    """Sirve el panel web del front end."""
    if _FRONTEND.is_file():
        return HTMLResponse(_FRONTEND.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Zotz API</h1><p>Panel no disponible.</p>")


class EngagementInput(BaseModel):
    """Datos de entrada para lanzar un engagement."""

    engagement_name: str = Field(min_length=1)
    company_name: str = Field(min_length=1)
    authorized_scope: str = Field(min_length=1)
    rules_of_engagement: str = ""

    @field_validator("authorized_scope")
    @classmethod
    def _scope_valido(cls, v: str) -> str:
        try:
            return validate_scope(v)
        except ScopeError as e:
            raise ValueError(str(e)) from e


@app.post("/api/engagements", dependencies=[Depends(_verificar_api_key)])
async def crear_engagement(
    payload: EngagementInput, request: Request
) -> dict[str, str]:
    """Crea un engagement y lo encola para ejecución en el worker."""
    await _verificar_rate_limit(request)
    inputs: dict[str, Any] = {
        "authorized_scope": payload.authorized_scope,
        "engagement_name": payload.engagement_name,
        "company_name": payload.company_name,
        "rules_of_engagement": payload.rules_of_engagement,
    }
    eng = manager.create(inputs)
    await _encolar(eng)
    log.info("api.creado", engagement=eng.id)
    return {"id": eng.id}


class DecisionAprobacion(BaseModel):
    """Decisión del operador en la fase de aprobación humana."""

    aprobado: bool
    comentario: str = ""


@app.post(
    "/api/engagements/{engagement_id}/approve",
    dependencies=[Depends(_verificar_api_key)],
)
async def aprobar_engagement(
    engagement_id: str, payload: DecisionAprobacion
) -> dict[str, str]:
    """Resuelve la aprobación humana pendiente de un engagement pausado."""
    eng = manager.get(engagement_id)
    if eng.status != "esperando_aprobacion":
        raise HTTPException(
            status_code=409,
            detail="El engagement no está esperando aprobación",
        )
    store.actualizar(engagement_id, status="running")
    await _encolar_resume(
        engagement_id, {"aprobado": payload.aprobado, "comentario": payload.comentario}
    )
    log.info("api.aprobacion_decidida", engagement=eng.id, aprobado=payload.aprobado)
    return {"status": "reanudando"}


@app.get("/api/engagements/{engagement_id}/events")
async def eventos_engagement(engagement_id: str) -> StreamingResponse:
    """Canal SSE con las fases del flujo en tiempo real."""
    manager.get(engagement_id)  # 404 si no existe
    return StreamingResponse(
        _sse_generator(engagement_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


async def _sse_generator(engagement_id: str) -> AsyncIterator[str]:
    """Lee el stream de Redis del engagement y lo retransmite como SSE.

    Usa un Redis Stream (no pub/sub) a propósito: si el cliente SSE se
    conecta después de que el worker ya publicó eventos (o reconecta tras un
    corte), lee desde el principio del stream en vez de perder los eventos
    ya emitidos — un pub/sub puro no tiene esa garantía.
    """
    yield _sse_event("conectado", "conectado")
    clave = _canal(engagement_id)
    ultimo_id = "0"
    intentos_fallidos = 0

    while True:
        cliente = redis_asyncio.from_url(_redis_url(), decode_responses=True)
        try:
            while True:
                resultado = await cliente.xread(
                    {clave: ultimo_id}, block=_SSE_BLOCK_MS, count=10
                )
                intentos_fallidos = 0  # una lectura exitosa resetea el backoff
                if not resultado:
                    continue  # timeout de bloqueo: sin eventos nuevos, reintenta
                _, mensajes = resultado[0]
                for msg_id, campos in mensajes:
                    ultimo_id = msg_id
                    yield _sse_event(campos["type"], campos["data"])
                    if campos["type"] in ("completado", "error"):
                        return
        except (redis_asyncio.ConnectionError, redis_asyncio.TimeoutError) as e:
            intentos_fallidos += 1
            log.error(
                "api.sse_redis_desconectado",
                engagement=engagement_id,
                intento=intentos_fallidos,
                error=str(e),
            )
            if intentos_fallidos > _SSE_MAX_RECONEXIONES:
                yield _sse_event(
                    "error", "Conexión con Redis perdida; no se pudo reconectar."
                )
                return
            espera = min(
                _SSE_BACKOFF_BASE_S * (2**intentos_fallidos), _SSE_BACKOFF_MAX_S
            )
            await asyncio.sleep(espera)
            continue
        finally:
            await cliente.aclose()


def _sse_event(nombre: str, data: str) -> str:
    """Serializa un evento SSE con el formato que espera el front."""
    payload = f'{{"data": {_json_str(data)}}}'
    return f"event: {nombre}\ndata: {payload}\n\n"


def _json_str(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


@app.get("/api/engagements/{engagement_id}/informe.md")
async def informe_md(engagement_id: str) -> PlainTextResponse:
    """Devuelve el informe final en Markdown."""
    eng = manager.get(engagement_id)
    if eng.status in ("running", "esperando_aprobacion"):
        raise HTTPException(status_code=409, detail="El informe aún no está listo")
    return PlainTextResponse(eng.informe_md, media_type="text/markdown")


@app.get("/api/engagements/{engagement_id}/informe.html")
async def informe_html(engagement_id: str) -> HTMLResponse:
    """Devuelve el informe final renderizado a HTML."""
    eng = manager.get(engagement_id)
    if eng.status in ("running", "esperando_aprobacion"):
        raise HTTPException(status_code=409, detail="El informe aún no está listo")
    return HTMLResponse(eng.informe_html)


@app.get("/api/engagements/{engagement_id}/graph")
async def get_graph(engagement_id: str) -> dict[str, Any]:
    """Devuelve la topología del grafo de red del engagement."""
    manager.get(engagement_id)  # 404 si no existe
    return store.obtener_grafo(engagement_id)
