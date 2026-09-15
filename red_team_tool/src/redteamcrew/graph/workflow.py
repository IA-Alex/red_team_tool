"""Orquestación del red team con LangGraph y LLM directo.

Los nodos llaman directamente al LLM de DeepInfra (sin CrewAI) y a las
herramientas puras de reconocimiento/análisis, manteniendo el flujo por fases
del engagement: Reconocimiento → Análisis → Validación → Aprobación Humana →
Simulación → Revisión → Informe.
"""

from __future__ import annotations

import os
from typing import Any

from langgraph.graph import END, StateGraph

from redteamcrew.config.prompts import agent_system_prompt, task_prompt
from redteamcrew.graph.state import AgentState
from redteamcrew.llm import chat
from redteamcrew.tools import osint_search, scan_ast
from redteamcrew.utils.logger import get_logger

log = get_logger("workflow")

MAX_ITERACIONES = 3
MIN_HALLAZGOS = 1

AGENT_RECON = "especialista_en_reconocimiento_de_superficie_de_ataque"
AGENT_ANALISTA = "analista_de_investigacion_y_correlacion_de_vulnerabilidades"
AGENT_EXPLOTADOR = "especialista_en_validacion_controlada_de_explotacion"
AGENT_ESTRATEGA = "correlacionador_de_simulacion_adversarial_y_rutas_de_ataque"
AGENT_FISCAL = "analista_senior_de_hallazgos_de_seguridad"
AGENT_CRONISTA = "autor_de_informes_de_seguridad"

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


def reconocimiento_nodo(state: AgentState) -> dict[str, Any]:
    """Fase 1: reconocimiento de superficie de ataque."""
    log.info("nodo.reconocimiento", iteracion=state["iteraciones"])
    inputs = state["inputs"]
    objetivo = state["objetivo"]

    osint_data = _run_osint(objetivo)

    system = agent_system_prompt(AGENT_RECON, inputs)
    user = task_prompt(
        TASK_RECON,
        inputs,
        contexto=f"Datos OSINT del objetivo {objetivo}:\n{osint_data}",
    )
    resultado = _llm(system, user)

    return {
        "superficie": resultado,
        "hallazgos": state["hallazgos"] + [resultado],
        "iteraciones": state["iteraciones"] + 1,
    }


def analisis_nodo(state: AgentState) -> dict[str, Any]:
    """Fase 2: análisis y correlación de vulnerabilidades."""
    log.info("nodo.analisis")
    inputs = state["inputs"]

    # Si el objetivo es código local, escanearlo estáticamente
    objetivo = state["objetivo"]
    ast_data = ""
    if os.path.exists(objetivo):
        ast_data = scan_ast(objetivo)

    contexto = (
        f"Superficie de ataque:\n{state['superficie']}\n\n"
        f"Análisis estático:\n{ast_data}"
    )
    system = agent_system_prompt(AGENT_ANALISTA, inputs)
    user = task_prompt(TASK_ANALISIS, inputs, contexto=contexto)
    resultado = _llm(system, user)

    return {"vulnerabilidades": resultado}


def validacion_nodo(state: AgentState) -> dict[str, Any]:
    """Fase 3: validación controlada de explotación."""
    log.info("nodo.validacion")
    inputs = state["inputs"]
    contexto = f"Vulnerabilidades identificadas:\n{state['vulnerabilidades']}"
    system = agent_system_prompt(AGENT_EXPLOTADOR, inputs)
    user = task_prompt(TASK_VALIDACION, inputs, contexto=contexto)
    return {"validacion": _llm(system, user)}


def aprobacion_nodo(state: AgentState) -> dict[str, Any]:
    """Fase 4: punto de control humano (aprobación de hallazgos).

    En modo automático se aprueba para continuar; en producción este nodo
    debería enlazarse con una revisión humana real.
    """
    log.info("nodo.aprobacion_humana")
    aprobacion = (
        f"APROBADO PARA CONTINUAR\n\nHallazgos validados:\n{state['validacion']}"
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
    contexto = f"Hallazgos revisados:\n{state['revision']}"
    system = agent_system_prompt(AGENT_CRONISTA, inputs)
    user = task_prompt(TASK_INFORME, inputs, contexto=contexto)
    return {"informe": _llm(system, user)}


def suficiencia_nodo(state: AgentState) -> dict[str, bool]:
    """Evalúa si hay suficientes hallazgos o se alcanzó el límite de iteraciones."""
    es_suficiente = (
        len(state["hallazgos"]) >= MIN_HALLAZGOS
        or state["iteraciones"] >= MAX_ITERACIONES
    )
    log.info("nodo.suficiencia", es_suficiente=es_suficiente)
    return {"es_suficiente": es_suficiente}


def condicion_iteracion(state: AgentState) -> str:
    return "fin" if state["es_suficiente"] else "reconocimiento"


def build_workflow() -> Any:
    """Construye y compila el grafo LangGraph del red team."""
    workflow = StateGraph(AgentState)

    workflow.add_node("reconocimiento", reconocimiento_nodo)
    workflow.add_node("suficiencia", suficiencia_nodo)
    workflow.add_node("analisis", analisis_nodo)
    workflow.add_node("validacion", validacion_nodo)
    workflow.add_node("aprobacion", aprobacion_nodo)
    workflow.add_node("simulacion", simulacion_nodo)
    workflow.add_node("revision", revision_nodo)
    workflow.add_node("informe", informe_nodo)

    workflow.set_entry_point("reconocimiento")

    # Iteración de reconocimiento hasta suficiencia, luego análisis
    workflow.add_edge("reconocimiento", "suficiencia")
    workflow.add_conditional_edges(
        "suficiencia",
        condicion_iteracion,
        {
            "reconocimiento": "reconocimiento",
            "fin": "analisis",
        },
    )

    workflow.add_edge("analisis", "validacion")
    workflow.add_edge("validacion", "aprobacion")
    workflow.add_edge("aprobacion", "simulacion")
    workflow.add_edge("simulacion", "revision")
    workflow.add_edge("revision", "informe")
    workflow.add_edge("informe", END)

    return workflow.compile()
