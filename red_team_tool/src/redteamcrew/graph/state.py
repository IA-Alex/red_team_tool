import operator
from typing import Annotated, Any, List, TypedDict


class AgentState(TypedDict):
    """Estado compartido para el flujo de trabajo de red team."""

    objetivo: str
    inputs: dict[str, Any]
    hallazgos: Annotated[List[str], operator.add]
    hosts: Annotated[List[dict[str, Any]], operator.add]
    hallazgos_verificados: Annotated[List[dict[str, Any]], operator.add]
    iteraciones: int
    es_suficiente: bool
    superficie: str
    vulnerabilidades: str
    validacion: str
    aprobacion: str
    rutas: str
    revision: str
    informe: str
    network_graph_data: dict[str, Any]
    attack_paths: Annotated[List[List[str]], operator.add]
    resultados_enum: Annotated[List[str], operator.add]
    descubrimientos_ssh: Annotated[List[dict[str, Any]], operator.add]
    plan_tareas: List[dict[str, Any]]


def estado_inicial(inputs: dict[str, Any]) -> AgentState:
    """Construye el estado inicial del flujo a partir de los inputs del engagement."""
    return {
        "objetivo": inputs["authorized_scope"],
        "inputs": inputs,
        "hallazgos": [],
        "hosts": [],
        "hallazgos_verificados": [],
        "iteraciones": 0,
        "es_suficiente": False,
        "superficie": "",
        "vulnerabilidades": "",
        "validacion": "",
        "aprobacion": "",
        "rutas": "",
        "revision": "",
        "informe": "",
        "network_graph_data": {"nodes": [], "links": []},
        "attack_paths": [],
        "resultados_enum": [],
        "descubrimientos_ssh": [],
        "plan_tareas": [],
    }
