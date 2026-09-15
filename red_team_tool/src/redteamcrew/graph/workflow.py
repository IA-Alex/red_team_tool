from typing import Any, Optional

from crewai import Task
from crewai.utilities.string_utils import interpolate_only
from langgraph.graph import END, StateGraph

from redteamcrew.crew import RedteamcrewCrew
from redteamcrew.graph.state import AgentState
from redteamcrew.utils.logger import get_logger

log = get_logger("workflow")

MAX_ITERACIONES = 5
MIN_HALLAZGOS = 2


def build_workflow(crew_instance: Optional[RedteamcrewCrew] = None) -> Any:
    # Usamos una instancia pasada o creamos una nueva solo cuando sea necesario
    redteam_crew = crew_instance or RedteamcrewCrew()

    def reconocimiento_nodo(state: AgentState) -> dict[str, Any]:
        log.info("nodo.reconocimiento", iteracion=state["iteraciones"])

        agente = redteam_crew.ocelotl_agent_recon()  # type: ignore[call-arg]
        tarea: Task = redteam_crew.descubrimiento_de_superficie_de_ataque()  # type: ignore[call-arg]
        inputs = state["inputs"]

        descripcion = interpolate_only(tarea.description, **inputs)
        contexto = interpolate_only(state["objetivo"], **inputs)

        resultado = agente.execute_task(task=tarea, context=contexto)
        if resultado is None:
            resultado = descripcion

        return {
            "hallazgos": state["hallazgos"] + [str(resultado)],
            "iteraciones": state["iteraciones"] + 1,
        }

    def analisis_nodo(state: AgentState) -> dict[str, bool]:
        log.info("nodo.analisis")
        es_suficiente = (
            len(state["hallazgos"]) >= MIN_HALLAZGOS
            or state["iteraciones"] >= MAX_ITERACIONES
        )
        log.info("analisis.resultado", es_suficiente=es_suficiente)
        return {"es_suficiente": es_suficiente}

    def condicion_iteracion(state: AgentState) -> str:
        return "fin" if state["es_suficiente"] else "reconocimiento"

    # Construcción del Grafo
    workflow = StateGraph(AgentState)

    workflow.add_node("reconocimiento", reconocimiento_nodo)
    workflow.add_node("analisis", analisis_nodo)

    workflow.set_entry_point("reconocimiento")
    workflow.add_edge("reconocimiento", "analisis")

    workflow.add_conditional_edges(
        "analisis",
        condicion_iteracion,
        {
            "reconocimiento": "reconocimiento",
            "fin": END,
        },
    )

    return workflow.compile()
