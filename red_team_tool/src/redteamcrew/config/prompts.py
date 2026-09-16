"""Carga e interpolación de prompts desde los YAML de configuración.

Sustituye la capa de CrewAI (agents.yaml/tasks.yaml + interpolación) con
lectura directa de los YAML y funciones de interpolación propias, de modo
que los nodos de langgraph puedan armar los prompts system/user.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

_CONFIG_DIR = Path(__file__).resolve().parent

# El contexto de cada fase se construye concatenando salidas de fases previas
# (LLM) y de herramientas externas (OSINT, nmap, nuclei) cuyo tamaño no está
# acotado — p. ej. crt.sh puede devolver miles de certificados para un
# dominio con muchos subdominios. Sin límite, fases tardías (revisión,
# informe) terminan concatenando varias salidas de LLM previas y pueden
# exceder la ventana de contexto del modelo, produciendo errores 4xx de la
# API o respuestas truncadas de forma silenciosa. ~12000 caracteres deja
# margen razonable para modelos con ventanas modestas (~8k tokens).
_MAX_CONTEXTO_CHARS = 12_000


def _limitar_contexto(contexto: str, limite: int = _MAX_CONTEXTO_CHARS) -> str:
    """Trunca ``contexto`` a ``limite`` caracteres, dejando constancia del recorte."""
    if len(contexto) <= limite:
        return contexto
    omitidos = len(contexto) - limite
    return (
        contexto[:limite]
        + f"\n\n[... contexto truncado: se omitieron {omitidos} caracteres "
        "para no exceder la ventana de contexto del modelo ...]"
    )


@lru_cache(maxsize=1)
def _load_agents() -> dict[str, Any]:
    with open(_CONFIG_DIR / "agents.yaml", encoding="utf-8") as f:
        return yaml.safe_load(f)  # type: ignore[no-any-return]


@lru_cache(maxsize=1)
def _load_tasks() -> dict[str, Any]:
    with open(_CONFIG_DIR / "tasks.yaml", encoding="utf-8") as f:
        return yaml.safe_load(f)  # type: ignore[no-any-return]


def sanitize_for_prompt(value: str) -> str:
    """Neutraliza construcciones que podrían inyectar instrucciones en el prompt.

    Los valores interpolados (alcance, nombre de empresa, salidas de
    herramientas) provienen en última instancia del operador o de fuentes
    externas (OSINT, nmap, nuclei) y se insertan directamente en el prompt
    del LLM. Se eliminan marcadores de rol/turno y delimitadores de bloque
    que un atacante podría usar para simular un cambio de rol del sistema.
    """
    peligrosos = (
        "system:", "assistant:", "user:",
        "<|im_start|>", "<|im_end|>", "```",
    )
    limpio = value
    for token in peligrosos:
        limpio = re.sub(re.escape(token), "", limpio, flags=re.IGNORECASE)
    return limpio


def interpolate(text: str, inputs: dict[str, Any]) -> str:
    """Interpola variables ``{clave}`` usando los inputs del engagement."""

    def _repl(match: re.Match[str]) -> str:
        valor = inputs.get(match.group(1), match.group(0))
        return sanitize_for_prompt(str(valor))

    return re.sub(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", _repl, text)


def agent_system_prompt(agent_key: str, inputs: dict[str, Any]) -> str:
    """Arma el prompt de sistema de un agente desde agents.yaml."""
    cfg = _load_agents().get(agent_key, {})
    role = interpolate(str(cfg.get("role", "")), inputs)
    goal = interpolate(str(cfg.get("goal", "")), inputs)
    backstory = str(cfg.get("backstory", ""))
    return f"Rol: {role}\nObjetivo: {goal}\nPerfil: {backstory}"


def task_prompt(
    task_key: str,
    inputs: dict[str, Any],
    contexto: str = "",
) -> str:
    """Arma el prompt de usuario de una tarea desde tasks.yaml."""
    cfg = _load_tasks().get(task_key, {})
    description = interpolate(str(cfg.get("description", "")), inputs)
    expected = interpolate(str(cfg.get("expected_output", "")), inputs)

    parts = [description, f"\n\n## Salida esperada\n{expected}"]
    if contexto:
        contexto = _limitar_contexto(contexto)
        parts.insert(0, f"## Contexto de fases previas\n{contexto}\n")
    return "\n".join(parts)
