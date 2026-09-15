import operator
from typing import Annotated, Any, List, TypedDict


class AgentState(TypedDict):
    """Estado compartido para el flujo de trabajo de red team."""

    objetivo: str
    inputs: dict[str, Any]
    hallazgos: Annotated[List[str], operator.add]
    iteraciones: int
    es_suficiente: bool
    superficie: str
    vulnerabilidades: str
    validacion: str
    aprobacion: str
    rutas: str
    revision: str
    informe: str
