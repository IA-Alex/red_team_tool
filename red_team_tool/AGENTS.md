# AGENTS.md — referencia rápida para asistentes de IA

> Este proyecto **migró de CrewAI a LangGraph** (ver commit "Migrar red team a
> LangGraph y CLI interactiva"). `crewai` ya no es una dependencia — no está
> en `pyproject.toml`. Si estás a punto de escribir código con patrones de
> CrewAI (`@CrewBase`, `Crew`, `Task`, `crew.kickoff()`, `crewai run`, etc.),
> **detente**: esos patrones no aplican a este repo.

## Dónde está la documentación real

- **[docs/ARQUITECTURA.md](docs/ARQUITECTURA.md)** — cómo funciona el sistema:
  componentes, el flujo de fases como grafo de LangGraph, la API REST/SSE, y
  cómo levantar todo localmente. Empieza aquí.
- **[docs/IDENTITY.md](docs/IDENTITY.md)** — identidad y convenciones de
  nombres de los agentes (`ocelotl_agent_*`) y tareas del engagement.
- **[README.md](README.md)** — instalación, uso de la CLI y estructura del
  código.

## Resumen mínimo de la arquitectura actual

- El flujo se define como un grafo de **LangGraph** en
  `src/redteamcrew/graph/workflow.py` (`build_workflow()`), no como una
  `Crew`.
- Cada nodo llama directamente al LLM de DeepInfra (`src/redteamcrew/llm.py`,
  vía `urllib`, sin LiteLLM ni `crewai.LLM`) o ejecuta herramientas puras en
  `src/redteamcrew/tools/`.
- Los roles y tareas siguen viviendo en `config/agents.yaml` /
  `config/tasks.yaml`, pero se cargan con `config/prompts.py`
  (`agent_system_prompt()` / `task_prompt()`), no con el `@CrewBase` de
  CrewAI.
- Dos puntos de entrada de proceso: la CLI (`main.py`, `build_workflow()` sin
  checkpointer) y la API + worker (`api/server.py` + `worker.py`,
  `build_workflow(require_approval=True)` con checkpointer en memoria para
  soportar `interrupt()` de LangGraph).

Para cualquier detalle de LangGraph que no esté cubierto aquí, consulta la
documentación oficial de LangGraph en vez de asumir comportamiento de CrewAI.
