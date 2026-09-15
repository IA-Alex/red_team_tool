from redteamcrew.crew import RedteamcrewCrew
from redteamcrew.graph.state import AgentState
from redteamcrew.graph.workflow import build_workflow


def _default_inputs():
    return {
        "authorized_scope": "example.com",
        "engagement_name": "test-engagement",
        "company_name": "Example Corp",
        "rules_of_engagement": (
            "Solo pruebas no destructivas autorizadas sobre example.com"
        ),
    }


def test_langgraph_workflow_real_execution():
    # Instancia real de la crew (se requiere configurar LLM_MODEL o tener
    # variables de entorno)
    redteam_crew = RedteamcrewCrew()

    # Construimos el workflow real
    app = build_workflow(crew_instance=redteam_crew)

    # Inicializamos el estado
    # Usamos un objetivo pequeño y seguro
    initial_state = AgentState(
        objetivo="example.com",
        inputs=_default_inputs(),
        hallazgos=[],
        iteraciones=0,
        es_suficiente=False,
    )

    # Ejecutamos el flujo
    # NOTA: Esto intentará llamar a los agentes reales.
    # Asegúrate de tener las variables de entorno configuradas
    # (ej. OPENAI_API_KEY, EXA_API_KEY)
    final_state = app.invoke(initial_state)

    # Verificaciones
    assert final_state["iteraciones"] >= 1
    assert "es_suficiente" in final_state
    print(f"Estado final: {final_state}")
