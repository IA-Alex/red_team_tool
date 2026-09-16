"""Worker arq: ejecuta el flujo LangGraph fuera del proceso de la API.

La API (``api/server.py``) solo encola trabajos; este proceso los ejecuta de
verdad (LLM, nmap, nuclei) y publica el progreso a un stream de Redis, de
donde la API lo retransmite a los clientes SSE. Así una llamada lenta nunca
bloquea el event loop que atiende peticiones HTTP — el problema reproducido
en vivo cuando todo corría en un único ``asyncio.create_task`` dentro del
proceso de la API.

Requiere un Redis corriendo (ver ``REDTEAMCREW_REDIS_URL``) y se lanza con::

    uv run redteamcrew-worker
"""

from __future__ import annotations

import json
import os
from typing import Any

import bleach
import markdown
from arq import run_worker
from arq.connections import RedisSettings
from langgraph.types import Command

from redteamcrew.api import store
from redteamcrew.graph.state import AgentState, estado_inicial
from redteamcrew.graph.workflow import EngagementRechazado, build_workflow
from redteamcrew.utils.logger import get_logger

log = get_logger("worker")

_REDIS_URL_ENV = "REDTEAMCREW_REDIS_URL"
_DEFAULT_REDIS_URL = "redis://localhost:6379"

# Nodos internos que no deben emitirse como fase (el chequeo de suficiencia
# del bucle de reconocimiento).
NODOS_INTERNOS = {"suficiencia"}

# Cuántos eventos conservar por stream y cuánto tiempo (para que un cliente
# SSE que reconecta pueda "ponerse al día" leyendo desde el principio).
_STREAM_MAXLEN = 500
_STREAM_TTL_SEGUNDOS = 86400

_app_cache: dict[str, Any] = {}

# El informe final se genera a partir de texto de LLM que incorpora, de forma
# indirecta, contenido no confiable (respuestas del objetivo, hallazgos de
# nuclei, OSINT). markdown.markdown() no escapa HTML embebido por defecto, así
# que cualquier marcado inyectado ahí (ej. un <meta http-equiv="refresh">)
# llegaría intacto al navegador. Se sanea con una allowlist explícita antes de
# persistirlo: es la única barrera del lado servidor, el iframe sandbox del
# frontend es defensa en profundidad, no sustituto.
_HTML_TAGS_PERMITIDAS = [
    "p", "br", "hr", "strong", "em", "b", "i", "u", "s", "del",
    "ul", "ol", "li", "blockquote", "code", "pre",
    "h1", "h2", "h3", "h4", "h5", "h6",
    "table", "thead", "tbody", "tr", "th", "td",
    "a", "span",
]
_HTML_ATTRS_PERMITIDOS = {"a": ["href", "title"]}


def _sanear_informe_html(html: str) -> str:
    return bleach.clean(
        html,
        tags=_HTML_TAGS_PERMITIDAS,
        attributes=_HTML_ATTRS_PERMITIDOS,
        protocols=["http", "https", "mailto"],
        strip=True,
    )


def _redis_url() -> str:
    return os.getenv(_REDIS_URL_ENV, _DEFAULT_REDIS_URL)


def _obtener_app() -> Any:
    """Grafo compilado, singleton dentro del proceso worker.

    Debe ser el mismo objeto durante toda la vida del proceso: el
    checkpointer que habilita la pausa de aprobación humana guarda su
    estado en memoria y solo puede reanudarse desde la misma instancia que
    lo pausó.
    """
    if "app" not in _app_cache:
        _app_cache["app"] = build_workflow(require_approval=True)
    return _app_cache["app"]


def _canal(engagement_id: str) -> str:
    return f"engagement:{engagement_id}:events"


async def _publicar(
    ctx: dict[str, Any], engagement_id: str, tipo: str, data: str
) -> None:
    redis_cliente = ctx["redis"]
    clave = _canal(engagement_id)
    await redis_cliente.xadd(
        clave,
        {"type": tipo, "data": data},
        maxlen=_STREAM_MAXLEN,
        approximate=True,
    )
    await redis_cliente.expire(clave, _STREAM_TTL_SEGUNDOS)


async def ejecutar_engagement(ctx: dict[str, Any], engagement_id: str) -> None:
    """Job de arq: lanza el flujo de un engagement desde el principio."""
    fila = store.obtener(engagement_id)
    if fila is None:
        log.error("worker.engagement_no_encontrado", engagement=engagement_id)
        return

    inputs = json.loads(fila["inputs"])
    inicial = estado_inicial(inputs)
    config = {"configurable": {"thread_id": engagement_id}}
    stream = _obtener_app().astream(
        inicial, config=config, stream_mode=["updates", "values"]
    )
    await _consumir(ctx, engagement_id, stream)


async def reanudar_engagement(
    ctx: dict[str, Any], engagement_id: str, decision: dict[str, Any]
) -> None:
    """Job de arq: reanuda un flujo pausado en la fase de aprobación humana."""
    config = {"configurable": {"thread_id": engagement_id}}
    stream = _obtener_app().astream(
        Command(resume=decision), config=config, stream_mode=["updates", "values"]
    )
    await _consumir(ctx, engagement_id, stream)


async def _consumir(ctx: dict[str, Any], engagement_id: str, stream: Any) -> None:
    """Recorre el stream del grafo publicando fases al stream de Redis.

    Se detiene en tres casos: el grafo se pausa (aprobación humana
    pendiente), termina con éxito, o lanza una excepción.
    """
    final_state: AgentState | None = None
    try:
        async for modo, payload in stream:
            if modo == "updates":
                if "__interrupt__" in payload:
                    interrupciones = payload.get("__interrupt__") or ()
                    valor = interrupciones[0].value if interrupciones else {}
                    store.actualizar(engagement_id, status="esperando_aprobacion")
                    await _publicar(
                        ctx,
                        engagement_id,
                        "aprobacion_requerida",
                        json.dumps(valor, ensure_ascii=False),
                    )
                    log.info("worker.aprobacion_requerida", engagement=engagement_id)
                    return
                for nombre_nodo in payload.keys():
                    if nombre_nodo in NODOS_INTERNOS:
                        continue
                    await _publicar(ctx, engagement_id, "fase", nombre_nodo)
                    log.info("worker.fase", engagement=engagement_id, nodo=nombre_nodo)
            elif modo == "values":
                final_state = payload

        _persistir_hallazgos(engagement_id, final_state)
        _persistir_informe(engagement_id, final_state)
        await _publicar(ctx, engagement_id, "completado", "ok")
        log.info("worker.completado", engagement=engagement_id)
    except EngagementRechazado as exc:
        # Un rechazo del operador es una decisión válida del engagement, no
        # una falla del sistema: se persiste con su propio status ('rechazado')
        # en vez de 'error', para que no se confunda con un fallo real de
        # herramienta/LLM en el panel ni en las métricas operativas.
        log.info("worker.rechazado", engagement=engagement_id, motivo=str(exc))
        _persistir_hallazgos(engagement_id, final_state)
        store.actualizar(engagement_id, status="rechazado", error=str(exc))
        await _publicar(ctx, engagement_id, "rechazado", str(exc))
    except Exception as exc:  # noqa: BLE001
        log.error("worker.error", engagement=engagement_id, error=str(exc))
        # Aunque la fase que falló no produjo informe, los hosts/hallazgos que
        # sí se ejecutaron y verificaron en fases anteriores (nmap/nuclei) no
        # deben perderse solo porque una fase posterior (típicamente una
        # llamada al LLM) falló — son datos reales, no narrativa descartable.
        _persistir_hallazgos(engagement_id, final_state)
        store.actualizar(engagement_id, status="error", error=str(exc))
        await _publicar(ctx, engagement_id, "error", str(exc))


def _persistir_hallazgos(engagement_id: str, final_state: AgentState | None) -> None:
    """Guarda los hosts/hallazgos verificados por herramienta, si los hay."""
    if final_state is None:
        return
    for host in final_state.get("hosts", []):
        store.agregar_host(
            engagement_id,
            host.get("host", ""),
            ip=host.get("ip", ""),
            puertos=host.get("puertos", []),
            descubierto_via="nmap",
        )
    for hallazgo in final_state.get("hallazgos_verificados", []):
        store.agregar_hallazgo(
            engagement_id,
            herramienta=hallazgo.get("herramienta", ""),
            severidad=hallazgo.get("severidad", "unknown"),
            titulo=hallazgo.get("titulo", ""),
            origen="herramienta",
            host=hallazgo.get("host", ""),
            evidencia=hallazgo.get("evidencia", ""),
        )
    
    # Persistir grafo
    if "network_graph_data" in final_state:
        store.guardar_grafo(
            engagement_id, 
            final_state["network_graph_data"],
            final_state.get("attack_paths", [])
        )


def _persistir_informe(engagement_id: str, final_state: AgentState | None) -> None:
    """Guarda el informe final (Markdown + HTML + JSON estructurado) del engagement."""
    informe = final_state.get("informe") or "" if final_state is not None else ""
    informe = informe or "(sin informe)"
    informe_html = _sanear_informe_html(
        markdown.markdown(informe, extensions=["tables", "fenced_code"])
    )
    
    informe_json = store.exportar_hallazgos_json(engagement_id)
    
    # Calcular resumen táctico (camino más corto)
    paths = final_state.get("attack_paths", []) if final_state else []
    tactical_summary = ""
    if paths:
        # Encontrar el camino más corto
        shortest = min(paths, key=len)
        tactical_summary = " -> ".join(shortest)
    
    store.actualizar(
        engagement_id,
        status="completed",
        informe_md=informe,
        informe_html=informe_html,
        informe_json=informe_json,
        tactical_summary=tactical_summary,
    )


class WorkerSettings:
    functions = [ejecutar_engagement, reanudar_engagement]
    redis_settings = RedisSettings.from_dsn(_redis_url())


def main() -> None:
    run_worker(WorkerSettings)  # type: ignore[arg-type]


if __name__ == "__main__":
    main()
