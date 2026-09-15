import os
from typing import Literal

from crewai import LLM, Agent, Crew, PlanningConfig, Process, Task
from crewai.project import CrewBase, agent, crew, task
from crewai_tools import (
    FileReadTool,
    JinaScrapeWebsiteTool,
    ScrapeWebsiteTool,
)

from redteamcrew.tools.osint_tool import OsintSearchTool


def get_llm() -> LLM:
    """Construye el LLM configurado para DeepInfra.

    El modelo se define con LLM_MODEL (formato ``deepinfra/<modelo>``).
    La API key se lee de DEEPINFRA_API_KEY, con fallback a OPENAI_API_KEY.
    """
    model = os.getenv("LLM_MODEL", "deepinfra/google/gemma-4-31B-it")
    api_key = os.getenv("DEEPINFRA_API_KEY") or os.getenv("OPENAI_API_KEY")
    return LLM(model=model, api_key=api_key)


def _planning(
    effort: Literal["low", "medium", "high"] = "low", max_steps: int = 20
) -> PlanningConfig:
    """Configuración de planificación/razonamiento previo del agente.

    Se usa ``reasoning_effort="low"`` por defecto porque el modelo DeepInfra
    (gemma) no siempre respeta el esquema JSON de la observación de pasos
    (``StepObservation``) que requieren los esfuerzos "medium"/"high".
    "low" salta la observación LLM por paso (heurística), manteniendo la
    planificación previa sin errores de parseo.
    """
    return PlanningConfig(
        reasoning_effort=effort,
        observe_steps=False,
        max_attempts=3,
        max_steps=max_steps,
    )


@CrewBase
class RedteamcrewCrew:
    """Redteamcrew crew"""


    @agent
    def ocelotl_agent_recon(self) -> Agent:
        return Agent(
            config=self.agents_config["especialista_en_reconocimiento_de_superficie_de_ataque"],  # type: ignore[arg-type,attr-defined,call-arg]
            tools=[OsintSearchTool(), ScrapeWebsiteTool(), JinaScrapeWebsiteTool()],
            planning_config=_planning(effort="low", max_steps=15),
            inject_date=True,
            allow_delegation=False,
            max_iter=30,
            max_rpm=None,
            max_execution_time=None,
            llm=get_llm(),
        )

    @agent
    def ocelotl_agent_analista(self) -> Agent:
        return Agent(
            config=self.agents_config["analista_de_investigacion_y_correlacion_de_vulnerabilidades"],  # type: ignore[arg-type,attr-defined,call-arg]
            tools=[OsintSearchTool(), ScrapeWebsiteTool(), JinaScrapeWebsiteTool()],
            planning_config=_planning(effort="low", max_steps=15),
            inject_date=True,
            allow_delegation=False,
            max_iter=30,
            max_rpm=None,
            max_execution_time=None,
            llm=get_llm(),
        )

    @agent
    def ocelotl_agent_explotador(self) -> Agent:
        return Agent(
            config=self.agents_config["especialista_en_validacion_controlada_de_explotacion"],  # type: ignore[arg-type,attr-defined,call-arg]
            tools=[OsintSearchTool(), ScrapeWebsiteTool()],
            planning_config=_planning(effort="low", max_steps=10),
            inject_date=True,
            allow_delegation=False,
            max_iter=30,
            max_rpm=None,
            max_execution_time=None,
            llm=get_llm(),
        )

    @agent
    def ocelotl_agent_estratega(self) -> Agent:
        return Agent(
            config=self.agents_config["correlacionador_de_simulacion_adversarial_y_rutas_de_ataque"],  # type: ignore[arg-type,attr-defined,call-arg]
            tools=[OsintSearchTool()],
            planning_config=_planning(effort="low", max_steps=20),
            inject_date=True,
            allow_delegation=False,
            max_iter=30,
            max_rpm=None,
            max_execution_time=None,
            llm=get_llm(),
        )

    @agent
    def ocelotl_agent_fiscal(self) -> Agent:
        return Agent(
            config=self.agents_config["analista_senior_de_hallazgos_de_seguridad"],  # type: ignore[arg-type,attr-defined,call-arg]
            tools=[],
            planning_config=_planning(effort="low", max_steps=15),
            inject_date=True,
            allow_delegation=False,
            max_iter=30,
            max_rpm=None,
            max_execution_time=None,
            llm=get_llm(),
        )

    @agent
    def ocelotl_agent_cronista(self) -> Agent:
        return Agent(
            config=self.agents_config["autor_de_informes_de_seguridad"],  # type: ignore[arg-type,attr-defined,call-arg]
            tools=[FileReadTool()],
            planning_config=_planning(effort="low", max_steps=10),
            inject_date=True,
            allow_delegation=False,
            max_iter=30,
            max_rpm=None,
            max_execution_time=None,
            llm=get_llm(),
        )




    @task
    def descubrimiento_de_superficie_de_ataque(self) -> Task:
        return Task(
            config=self.tasks_config["descubrimiento_de_superficie_de_ataque"],  # type: ignore[arg-type,attr-defined,call-arg]
            markdown=False,


        )

    @task
    def identificacion_de_vulnerabilidades(self) -> Task:
        return Task(
            config=self.tasks_config["identificacion_de_vulnerabilidades"],  # type: ignore[arg-type,attr-defined,call-arg]
            markdown=False,


        )

    @task
    def validacion_controlada_de_explotacion(self) -> Task:
        return Task(
            config=self.tasks_config["validacion_controlada_de_explotacion"],  # type: ignore[arg-type,attr-defined,call-arg]
            markdown=False,


        )

    @task
    def aprobacion_humana_de_hallazgos(self) -> Task:
        return Task(
            config=self.tasks_config["aprobacion_humana_de_hallazgos"],  # type: ignore[arg-type,attr-defined,call-arg]
            markdown=False,


        )

    @task
    def simulacion_de_rutas_de_ataque(self) -> Task:
        return Task(
            config=self.tasks_config["simulacion_de_rutas_de_ataque"],  # type: ignore[arg-type,attr-defined,call-arg]
            markdown=False,


        )

    @task
    def revision_y_clasificacion_de_hallazgos(self) -> Task:
        return Task(
            config=self.tasks_config["revision_y_clasificacion_de_hallazgos"],  # type: ignore[arg-type,attr-defined,call-arg]
            markdown=False,


        )

    @task
    def generacion_del_informe_final(self) -> Task:
        return Task(
            config=self.tasks_config["generacion_del_informe_final"],  # type: ignore[arg-type,attr-defined,call-arg]
            markdown=False,


        )


    @crew
    def crew(self) -> Crew:
        """Creates the Redteamcrew crew"""

        return Crew(
            agents=self.agents,  # type: ignore[attr-defined]
            tasks=self.tasks,  # type: ignore[attr-defined]
            process=Process.sequential,
            verbose=True,
            memory=True,
            embedder={"provider": "onnx"},
            chat_llm=get_llm(),
        )
