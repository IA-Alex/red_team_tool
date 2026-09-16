"""Orquestación del red team con LangGraph y LLM directo.

Los nodos llaman directamente al LLM de DeepInfra (sin CrewAI) y a las
herramientas puras de reconocimiento/análisis, manteniendo el flujo por fases
del engagement: Reconocimiento → Análisis → Validación → Aprobación Humana →
Simulación → Revisión → Informe.
"""

from __future__ import annotations

import os
from dataclasses import asdict
from pathlib import Path
from typing import Any

import networkx as nx
from networkx.readwrite import json_graph
from langgraph.checkpoint.memory import MemorySaver
# ...
def _actualizar_grafo(state: AgentState, nuevo_grafo: nx.Graph) -> dict[str, Any]:
    """Serializa el grafo networkx para persistirlo en AgentState."""
    data = json_graph.node_link_data(nuevo_grafo, edges="links")
    return {"network_graph_data": data}

def _obtener_grafo(state: AgentState) -> nx.Graph:
    """Deserializa el grafo desde AgentState."""
    data = state.get("network_graph_data", {"nodes": [], "links": []})
    return json_graph.node_link_graph(data, edges="links")

from langgraph.graph import END, StateGraph
from langgraph.types import interrupt

from redteamcrew.config.prompts import agent_system_prompt, task_prompt
from redteamcrew.graph.state import AgentState
from redteamcrew.llm import chat
from redteamcrew.scope import ScopeError
from redteamcrew.tools import osint_search, run_nmap, run_nuclei, run_poc, scan_ast
from redteamcrew.utils.logger import get_logger

log = get_logger("workflow")

MAX_ITERACIONES = 3
MIN_HALLAZGOS = 1


class EngagementRechazado(RuntimeError):
    """El operador rechazó el engagement en la fase de aprobación humana.

    Se distingue de un ``RuntimeError`` genérico (fallo real de una fase)
    para que el worker pueda persistir un estado 'rechazado' en vez de
    'error': un rechazo humano es una decisión válida del engagement, no una
    falla del sistema.
    """

# Raíz de confianza desde la que se permite escanear código local. Si no está
# configurada, el análisis estático de código local queda deshabilitado: el
# alcance autorizado del engagement (dominio/IP externo) NUNCA se interpreta
# como ruta de archivo del servidor.
_SCAN_ROOT_ENV = "REDTEAMCREW_SCAN_ROOT"

AGENT_RECON = "ocelotl_agent_recon"
AGENT_ANALISTA = "ocelotl_agent_analista"
AGENT_EXPLOTADOR = "ocelotl_agent_explotador"
AGENT_ESTRATEGA = "ocelotl_agent_estratega"
AGENT_FISCAL = "ocelotl_agent_fiscal"
AGENT_CRONISTA = "ocelotl_agent_cronista"

TASK_RECON = "descubrimiento_de_superficie_de_ataque"
TASK_ANALISIS = "identificacion_de_vulnerabilidades"
TASK_VALIDACION = "validacion_controlada_de_explotacion"
TASK_SIMULACION = "simulacion_de_rutas_de_ataque"
TASK_REVISION = "revision_y_clasificacion_de_hallazgos"
TASK_INFORME = "generacion_del_informe_final"


def _llm(system: str, user: str) -> str:
    return chat(
        [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        max_tokens=4096,
    )


def _run_osint(objetivo: str) -> str:
    """Recolecta información OSINT del objetivo (dominio/IP)."""
    resultados = []
    for op in ("dns", "subdomains", "certs", "ip"):
        resultados.append(f"--- {op} ---\n{osint_search(objetivo, operation=op)}")
    return "\n".join(resultados)


def _run_recon_activo(objetivo: str) -> tuple[list[dict[str, Any]], str]:
    """Escaneo activo (nmap) sobre el primer objetivo del alcance.

    Devuelve los hosts/puertos descubiertos (para persistir en el estado) y un
    resumen en texto plano para el contexto del prompt. Nunca lanza excepción
    hacia el nodo: un fallo de recon activo (objetivo fuera de alcance,
    herramienta ausente, timeout) se registra y se continúa solo con OSINT
    pasivo, igual que antes de esta fase.
    """
    objetivo_primario = objetivo.split(",", maxsplit=1)[0].strip()
    if not objetivo_primario:
        return [], "(sin objetivo válido para recon activo)"

    try:
        resultado = run_nmap(objetivo_primario, objetivo)
    except ScopeError as e:
        log.error("nodo.reconocimiento.scope_error", error=str(e))
        return [], f"(recon activo omitido: {e})"
    except RuntimeError as e:
        log.warning("nodo.reconocimiento.nmap_error", error=str(e))
        return [], f"(recon activo falló: {e})"

    if not resultado.puertos:
        return [], (
            f"Sin puertos abiertos detectados en {objetivo_primario} (top 100 TCP)."
        )

    puertos = [asdict(p) for p in resultado.puertos]
    hosts = [{"host": resultado.host, "ip": "", "puertos": puertos}]
    resumen = "\n".join(
        f"- {p['numero']}/{p['protocolo']} {p['servicio']} {p['version']}".strip()
        for p in puertos
    )
    return hosts, f"Puertos abiertos en {resultado.host} (nmap top-100 TCP):\n{resumen}"


def reconocimiento_nodo(state: AgentState) -> dict[str, Any]:
    """Fase 1: reconocimiento de superficie de ataque (OSINT pasivo + nmap activo)."""
    log.info("nodo.reconocimiento", iteracion=state["iteraciones"])
    inputs = state["inputs"]
    objetivo = state["objetivo"]

    osint_data = _run_osint(objetivo)
    hosts_descubiertos, recon_activo_resumen = _run_recon_activo(objetivo)

    # Actualizar grafo
    grafo = _obtener_grafo(state)
    for h in hosts_descubiertos:
        grafo.add_node(h["host"], type="host")
        for p in h["puertos"]:
            grafo.add_node(f"{h['host']}:{p['numero']}", type="service", service=p["servicio"])
            grafo.add_edge(h["host"], f"{h['host']}:{p['numero']}")
    
    grafo_actualizado = _actualizar_grafo(state, grafo)

    system = agent_system_prompt(AGENT_RECON, inputs)
    user = task_prompt(
        TASK_RECON,
        inputs,
        contexto=(
            f"Datos OSINT del objetivo {objetivo}:\n{osint_data}\n\n"
            f"Reconocimiento activo (nmap):\n{recon_activo_resumen}"
        ),
    )
    resultado = _llm(system, user)

    return {
        "superficie": resultado,
        "hallazgos": state["hallazgos"] + [resultado],
        "hosts": hosts_descubiertos,
        "iteraciones": state["iteraciones"] + 1,
        **grafo_actualizado
    }


def _resolver_ruta_codigo_local(solicitada: str | None) -> str | None:
    """Devuelve una ruta local segura a escanear, o ``None`` si no aplica.

    El escaneo estático de código local solo se activa si el operador
    configuró explícitamente ``REDTEAMCREW_SCAN_ROOT`` (una raíz de
    confianza) y la ruta solicitada (``inputs['local_code_path']``) cae
    dentro de esa raíz. Nunca se deriva del alcance autorizado del
    engagement, que es un dominio/IP/CIDR externo, no una ruta de servidor.
    """
    if not solicitada:
        return None

    root_raw = os.getenv(_SCAN_ROOT_ENV)
    if not root_raw:
        log.warning(
            "analisis.scan_deshabilitado",
            motivo=f"{_SCAN_ROOT_ENV} no configurado",
        )
        return None

    root = Path(root_raw).resolve()
    solicitud = Path(solicitada)
    candidata = (
        solicitud.resolve()
        if solicitud.is_absolute()
        else (root / solicitud).resolve()
    )
    try:
        candidata.relative_to(root)
    except ValueError:
        log.warning("analisis.scan_fuera_de_raiz", solicitado=solicitada)
        return None

    if not candidata.exists():
        return None
    return str(candidata)


def _run_nuclei_sobre_hosts(
    hosts: list[dict[str, Any]], objetivo: str
) -> tuple[list[dict[str, Any]], str]:
    """Corre nuclei contra cada host y puerto descubierto en recon.

    Igual que el recon activo: un fallo por host (fuera de alcance, timeout)
    se registra y se salta ese host, sin abortar el nodo completo.
    """
    hallazgos: list[dict[str, Any]] = []
    for host_info in hosts:
        host = host_info.get("host", "")
        if not host:
            continue
        
        puertos = host_info.get("puertos", [])
        # Si no hay puertos descubiertos, escanear el host pelado
        targets_to_scan = [f"http://{host}:{p['numero']}" for p in puertos if p['servicio'].startswith('http')]
        if not targets_to_scan:
            targets_to_scan = [host]

        for target_url in targets_to_scan:
            try:
                # El host para scope check es 'host'
                resultados = run_nuclei(host, objetivo, target_url=target_url)
            except ScopeError as e:
                log.error("nodo.analisis.scope_error", host=host, error=str(e))
                continue
            except RuntimeError as e:
                log.warning("nodo.analisis.nuclei_error", host=host, error=str(e))
                continue
            for f in resultados:
                hallazgos.append(
                    {
                        "host": f.host or host,
                        "herramienta": "nuclei",
                        "severidad": f.severidad,
                        "titulo": f.nombre,
                        "evidencia": f.evidencia,
                        "plantilla": f.plantilla,
                        "origen": "herramienta",
                    }
                )

    if not hallazgos:
        resumen = "(sin hallazgos verificados por herramienta)"
    else:
        resumen = "\n".join(
            f"- [{h['severidad'].upper()}] {h['titulo']} en {h['host']} "
            f"({h['evidencia']})"
            for h in hallazgos
        )
    return hallazgos, resumen


def analisis_nodo(state: AgentState) -> dict[str, Any]:
    """Fase 2: análisis y correlación de vulnerabilidades (especializado + nuclei + LLM)."""
    log.info("nodo.analisis")
    inputs = state["inputs"]
    objetivo = state["objetivo"]

    # 1. Ejecutar el plan de tareas adaptativo (enumeración especializada por servicio)
    resultados_enum = []
    descubrimientos_ssh = []
    for tarea in state.get("plan_tareas", []):
        try:
            res = tarea["tool"](tarea["target"], objetivo)
            resultados_enum.append(f"{res.tool} en {res.target}: {res.output}")
            usuarios = getattr(res, "usuarios", None)
            if usuarios:
                descubrimientos_ssh.append({"host": tarea["host"], "usuarios": usuarios})
        except ScopeError as e:
            log.error("nodo.analisis.scope_error", tarea=tarea, error=str(e))
        except Exception as e:
            log.warning("nodo.analisis.enum_error", tarea=tarea, error=str(e))

    # 2. Ejecutar nuclei sobre los hosts descubiertos en recon
    hallazgos_verificados, nuclei_resumen = _run_nuclei_sobre_hosts(
        state["hosts"], objetivo
    )

    # 3. Correlación LLM del contexto recolectado
    contexto = (
        f"Superficie descubierta:\n{state['superficie']}\n\n"
        "Resultados de enumeración especializada por servicio:\n"
        + ("\n".join(resultados_enum) or "(sin tareas de enumeración planificadas)")
        + f"\n\nHallazgos verificados por nuclei:\n{nuclei_resumen}"
    )
    system = agent_system_prompt(AGENT_ANALISTA, inputs)
    user = task_prompt(TASK_ANALISIS, inputs, contexto=contexto)
    resultado = _llm(system, user)

    return {
        "vulnerabilidades": resultado,
        "hallazgos_verificados": hallazgos_verificados,
        "resultados_enum": resultados_enum,
        "descubrimientos_ssh": descubrimientos_ssh,
    }


def _resumen_validacion(resultados_poc: list[dict[str, Any]]) -> str:
    """Resume los resultados de PoC en texto plano para las fases siguientes."""
    if not resultados_poc:
        return "(sin PoCs ejecutadas: ningún hallazgo fue aprobado o no había hallazgos verificados)"
    lineas = [
        f"- {r['hallazgo']}: {'PoC exitosa' if r['poc_exitosa'] else 'PoC sin éxito'} — {r['detalles']}"
        for r in resultados_poc
    ]
    return "\n".join(lineas)


def explotacion_manual_nodo(state: AgentState) -> dict[str, Any]:
    """Fase 3 (modo manual): valida cada hallazgo mediante PoC, con aprobación
    humana por hallazgo vía human-in-the-loop de LangGraph (``interrupt``).

    Requiere que el grafo se compile con un checkpointer. Solo debe usarse en
    el flujo expuesto por la API (``require_approval=True``); para la CLI usar
    :func:`explotacion_auto_nodo`.
    """
    log.info("nodo.explotacion", modo="manual")
    objetivo = state["objetivo"]
    hallazgos_verificados = state.get("hallazgos_verificados", [])
    resultados_poc = []

    for h in hallazgos_verificados:
        decision = interrupt({
            "tipo": "aprobacion_poc",
            "hallazgo": h["titulo"],
            "target": h["host"]
        })

        if isinstance(decision, dict) and decision.get("aprobado"):
            log.info("nodo.explotacion.ejecutando", hallazgo=h["titulo"])
            res = run_poc(h["host"], h["plantilla"], objetivo)
            resultados_poc.append({
                "hallazgo": h["titulo"],
                "poc_exitosa": res.success,
                "detalles": res.output
            })
        else:
            log.info("nodo.explotacion.rechazado", hallazgo=h["titulo"])

    return {
        "resultados_poc": resultados_poc,
        "validacion": _resumen_validacion(resultados_poc),
    }


def explotacion_auto_nodo(state: AgentState) -> dict[str, Any]:
    """Fase 3 (modo automático): ejecuta PoC para todos los hallazgos
    verificados sin pausar el grafo.

    Solo debe usarse en la CLI/tests locales (``require_approval=False``),
    donde el grafo se compila sin checkpointer y por tanto no puede pausarse
    con ``interrupt``. El operador ya confirmó el engagement de forma
    interactiva antes de lanzar el flujo.
    """
    log.info("nodo.explotacion", modo="auto")
    objetivo = state["objetivo"]
    hallazgos_verificados = state.get("hallazgos_verificados", [])
    resultados_poc = []

    for h in hallazgos_verificados:
        log.info("nodo.explotacion.ejecutando", hallazgo=h["titulo"])
        res = run_poc(h["host"], h["plantilla"], objetivo)
        resultados_poc.append({
            "hallazgo": h["titulo"],
            "poc_exitosa": res.success,
            "detalles": res.output
        })

    return {
        "resultados_poc": resultados_poc,
        "validacion": _resumen_validacion(resultados_poc),
    }


def aprobacion_auto_nodo(state: AgentState) -> dict[str, Any]:
    """Fase 4 (modo automático): aprueba sin intervención humana.

    Solo debe usarse en la CLI/tests locales, donde el operador ya confirmó
    el engagement de forma interactiva antes de lanzar el flujo. Para
    cualquier flujo expuesto por la API, usar :func:`aprobacion_manual_nodo`.
    """
    log.info("nodo.aprobacion_humana", modo="auto")
    aprobacion = (
        f"APROBADO AUTOMÁTICAMENTE\n\nHallazgos validados:\n{state['validacion']}"
    )
    return {"aprobacion": aprobacion}


def aprobacion_manual_nodo(state: AgentState) -> dict[str, Any]:
    """Fase 4 (modo manual): pausa el grafo hasta recibir una decisión humana.

    Usa el mecanismo nativo de human-in-the-loop de LangGraph (``interrupt``):
    el grafo se detiene aquí y solo continúa cuando alguien reanuda la
    ejecución con ``Command(resume={"aprobado": bool, "comentario": str})``.
    Requiere que el grafo se compile con un checkpointer.
    """
    log.info("nodo.aprobacion_humana", modo="manual")
    decision = interrupt(
        {
            "tipo": "aprobacion_humana",
            "validacion": state["validacion"],
        }
    )
    if isinstance(decision, dict):
        aprobado = bool(decision.get("aprobado", False))
        comentario = decision.get("comentario", "")
    else:
        aprobado, comentario = False, ""

    if not aprobado:
        raise EngagementRechazado(
            "Engagement rechazado por el operador en la fase de aprobación "
            f"humana. Comentario: {comentario or '(sin comentario)'}"
        )

    aprobacion = (
        "APROBADO POR OPERADOR\n"
        f"Comentario: {comentario or '(sin comentario)'}\n\n"
        f"Hallazgos validados:\n{state['validacion']}"
    )
    return {"aprobacion": aprobacion}


def simulacion_nodo(state: AgentState) -> dict[str, Any]:
    """Fase 5: simulación adversarial y rutas de ataque."""
    log.info("nodo.simulacion")
    inputs = state["inputs"]
    contexto = f"Hallazgos aprobados:\n{state['aprobacion']}"
    system = agent_system_prompt(AGENT_ESTRATEGA, inputs)
    user = task_prompt(TASK_SIMULACION, inputs, contexto=contexto)
    return {"rutas": _llm(system, user)}


def revision_nodo(state: AgentState) -> dict[str, Any]:
    """Fase 6: revisión y clasificación final de hallazgos."""
    log.info("nodo.revision")
    inputs = state["inputs"]
    contexto = "\n\n".join(
        [
            f"Superficie:\n{state['superficie']}",
            f"Vulnerabilidades:\n{state['vulnerabilidades']}",
            f"Validación:\n{state['validacion']}",
            f"Rutas:\n{state['rutas']}",
        ]
    )
    system = agent_system_prompt(AGENT_FISCAL, inputs)
    user = task_prompt(TASK_REVISION, inputs, contexto=contexto)
    return {"revision": _llm(system, user)}


def informe_nodo(state: AgentState) -> dict[str, Any]:
    """Fase 7: generación del informe final."""
    log.info("nodo.informe")
    inputs = state["inputs"]

    if state["hallazgos_verificados"]:
        tabla_verificados = "\n".join(
            f"- [{h['severidad'].upper()}] {h['titulo']} en {h['host']} "
            f"(herramienta: {h['herramienta']}, evidencia: {h['evidencia']})"
            for h in state["hallazgos_verificados"]
        )
    else:
        tabla_verificados = (
            "(ningún hallazgo verificado por herramienta en este engagement)"
        )

    contexto = (
        f"Hallazgos revisados:\n{state['revision']}\n\n"
        "Hallazgos verificados por ejecución real de herramientas (incluir "
        "explícitamente en el informe, distinguidos de cualquier inferencia "
        "del modelo):\n"
        f"{tabla_verificados}\n\n"
        "INSTRUCCIÓN DE SEGURIDAD ABSOLUTA:\n"
        "1. Cualquier hallazgo que NO esté presente en la lista de 'Hallazgos "
        "verificados por ejecución real' DEBE ser ignorado por completo.\n"
        "2. La confianza en la generación es binaria: si no fue detectado por "
        "la herramienta, NO EXISTE para este informe.\n"
        "3. NO inventes servicios, puertos o vulnerabilidades que no estén en "
        "la sección de 'Evidencia Técnica'."
    )
    system = agent_system_prompt(AGENT_CRONISTA, inputs)
    user = task_prompt(TASK_INFORME, inputs, contexto=contexto)
    return {"informe": _llm(system, user)}


def suficiencia_nodo(state: AgentState) -> dict[str, bool]:
    """Evalúa si hay suficientes hallazgos o se alcanzó el límite de iteraciones.

    Nota: la condición de corte sigue basada en intentos de reconocimiento
    (``hallazgos`` de texto) y no en cantidad de hosts activos descubiertos a
    propósito — un objetivo sin puertos abiertos es un resultado válido, no
    una señal de "seguir escaneando". El conteo de hosts reales se registra
    solo con fines de observabilidad.
    """
    es_suficiente = (
        len(state["hallazgos"]) >= MIN_HALLAZGOS
        or state["iteraciones"] >= MAX_ITERACIONES
    )
    log.info(
        "nodo.suficiencia",
        es_suficiente=es_suficiente,
        hosts_descubiertos=len(state["hosts"]),
    )
    return {"es_suficiente": es_suficiente}


def condicion_iteracion(state: AgentState) -> str:
    return "fin" if state["es_suficiente"] else "reconocimiento"


from redteamcrew.tools import enum_tool
from redteamcrew.utils.graph_utils import find_attack_path, get_nodes_by_type, add_privilege_edge, add_identity_node

SERVICE_TOOLS = {
    "ssh": enum_tool.run_ssh_enum,
    "http": enum_tool.run_http_enum,
    "https": enum_tool.run_http_enum,
}

def adaptacion_nodo(state: AgentState) -> dict[str, Any]:
    """Fase intermedia: planifica escaneos según los servicios encontrados."""
    log.info("nodo.adaptacion")
    plan = []
    for host_info in state["hosts"]:
        host = host_info.get("host", "")
        for p in host_info.get("puertos", []):
            servicio = p["servicio"].lower()
            if servicio in SERVICE_TOOLS:
                target = (
                    f"{servicio}://{host}:{p['numero']}"
                    if servicio in ("http", "https")
                    else host
                )
                plan.append({
                    "host": host,
                    "puerto": p["numero"],
                    "servicio": servicio,
                    "target": target,
                    "tool": SERVICE_TOOLS[servicio]
                })
    return {"plan_tareas": plan}

def enum_privs_nodo(state: AgentState) -> dict[str, Any]:
    """Fase intermedia: extrae privilegios del grafo y los formaliza."""
    log.info("nodo.enum_privs")
    grafo = _obtener_grafo(state)

    for descubrimiento in state.get("descubrimientos_ssh", []):
        host = descubrimiento.get("host", "")
        if not host:
            continue
        for user in descubrimiento.get("usuarios", []):
            if user:
                add_identity_node(grafo, user, "user")
                add_privilege_edge(grafo, user, host, "HAS_ACCESS")

    return _actualizar_grafo(state, grafo)


def pathfinding_nodo(state: AgentState) -> dict[str, Any]:
    """Fase intermedia: calcula rutas de ataque desde hosts hacia identidades."""
    log.info("nodo.pathfinding")
    grafo = _obtener_grafo(state)
    hosts = get_nodes_by_type(grafo, "host")
    usuarios = get_nodes_by_type(grafo, "user")

    rutas = []
    for origen in hosts:
        for destino in usuarios:
            camino = find_attack_path(grafo, origen, destino)
            if camino:
                rutas.append(camino)

    log.info("nodo.pathfinding.rutas", total=len(rutas))
    return {"attack_paths": rutas}


def build_workflow(*, require_approval: bool = False) -> Any:
    """Construye y compila el grafo LangGraph del red team."""
    workflow = StateGraph(AgentState)

    workflow.add_node("reconocimiento", reconocimiento_nodo)
    workflow.add_node("suficiencia", suficiencia_nodo)
    workflow.add_node("adaptacion", adaptacion_nodo)
    workflow.add_node("analisis", analisis_nodo)
    workflow.add_node("enum_privs", enum_privs_nodo)
    workflow.add_node("pathfinding", pathfinding_nodo)
    workflow.add_node(
        "explotacion",
        explotacion_manual_nodo if require_approval else explotacion_auto_nodo,
    )
    workflow.add_node(
        "aprobacion",
        aprobacion_manual_nodo if require_approval else aprobacion_auto_nodo,
    )
    workflow.add_node("simulacion", simulacion_nodo)
    workflow.add_node("revision", revision_nodo)
    workflow.add_node("informe", informe_nodo)

    workflow.set_entry_point("reconocimiento")

    # Iteración de reconocimiento hasta suficiencia, luego adaptación
    workflow.add_edge("reconocimiento", "suficiencia")
    workflow.add_conditional_edges(
        "suficiencia",
        condicion_iteracion,
        {
            "reconocimiento": "reconocimiento",
            "fin": "adaptacion",
        },
    )
    
    # Flujo principal
    workflow.add_edge("adaptacion", "analisis")
    workflow.add_edge("analisis", "enum_privs")
    workflow.add_edge("enum_privs", "pathfinding")
    workflow.add_edge("pathfinding", "explotacion")
    workflow.add_edge("explotacion", "aprobacion")
    workflow.add_edge("aprobacion", "simulacion")
    workflow.add_edge("simulacion", "revision")
    workflow.add_edge("revision", "informe")
    workflow.add_edge("informe", END)

    checkpointer = MemorySaver() if require_approval else None
    return workflow.compile(checkpointer=checkpointer)
