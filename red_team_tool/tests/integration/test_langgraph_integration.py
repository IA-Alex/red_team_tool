from typing import Any

from redteamcrew.graph.state import AgentState
from redteamcrew.graph.workflow import build_workflow


def _default_inputs() -> dict[str, Any]:
    return {
        "authorized_scope": "example.com",
        "engagement_name": "test-engagement",
        "company_name": "Example Corp",
        "rules_of_engagement": (
            "Solo pruebas no destructivas autorizadas sobre example.com"
        ),
    }


def test_langgraph_workflow_compiles() -> None:
    """El grafo LangGraph se construye y compila sin errores."""
    app = build_workflow()
    assert app is not None


def test_langgraph_workflow_real_execution() -> None:
    # Requiere DEEPINFRA_API_KEY configurada.
    app = build_workflow()

    initial_state = AgentState(
        objetivo="example.com",
        inputs=_default_inputs(),
        hallazgos=[],
        iteraciones=0,
        es_suficiente=False,
        superficie="",
        vulnerabilidades="",
        validacion="",
        aprobacion="",
        rutas="",
        revision="",
        informe="",
    )

    final_state = app.invoke(initial_state)

    assert final_state["iteraciones"] >= 1
    assert "es_suficiente" in final_state
    assert final_state["informe"]
    print(f"Estado final: {final_state}")
