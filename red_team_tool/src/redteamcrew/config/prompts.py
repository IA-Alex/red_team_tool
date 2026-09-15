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


@lru_cache(maxsize=1)
def _load_agents() -> dict[str, Any]:
    with open(_CONFIG_DIR / "agents.yaml", encoding="utf-8") as f:
        return yaml.safe_load(f)  # type: ignore[no-any-return]


@lru_cache(maxsize=1)
def _load_tasks() -> dict[str, Any]:
    with open(_CONFIG_DIR / "tasks.yaml", encoding="utf-8") as f:
        return yaml.safe_load(f)  # type: ignore[no-any-return]


def interpolate(text: str, inputs: dict[str, Any]) -> str:
    """Interpola variables ``{clave}`` usando los inputs del engagement."""

    def _repl(match: re.Match[str]) -> str:
        return str(inputs.get(match.group(1), match.group(0)))

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
        parts.insert(0, f"## Contexto de fases previas\n{contexto}\n")
    return "\n".join(parts)
