"""Cliente LLM directo para DeepInfra.

Habla con la API de chat de DeepInfra (compatible con OpenAI) usando solo la
librería estándar (``urllib``), sin depender de crewai ni litellm. Esto reduce
drásticamente la memoria y el tiempo de arranque del proceso.
"""

from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path
from typing import Any

from redteamcrew.utils.logger import get_logger

log = get_logger("llm")

DEFAULT_MODEL = "google/gemma-2-27b-it"
CHAT_URL = "https://api.deepinfra.com/v1/chat/completions"
# Una completion de max_tokens=4096 en un modelo de ~27B puede tardar ~100s
# incluso sin carga (medido en vivo contra DeepInfra); con el contexto real
# de nmap/nuclei que ahora se inyecta en los prompts de los nodos, 120s
# quedaba al límite y producía timeouts intermitentes.
TIMEOUT = 300

_env_loaded: dict[str, bool] = {"done": False}


def _load_env_file() -> None:
    """Carga las variables del archivo .env en el entorno.

    El archivo .env del proyecto tiene prioridad sobre las variables ya
    exportadas en el shell, de modo que la configuración del repo es la fuente
    de verdad.
    """
    if _env_loaded["done"]:
        return
    _env_loaded["done"] = True

    env_file = Path(".env")
    if not env_file.is_file():
        return

    for raw in env_file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            os.environ[key] = value


def get_api_key() -> str:
    """Devuelve la API key de DeepInfra (fallback a OPENAI_API_KEY), o "" si falta."""
    _load_env_file()
    return os.getenv("DEEPINFRA_API_KEY") or os.getenv("OPENAI_API_KEY") or ""


def require_api_key() -> str:
    """Como ``get_api_key`` pero falla de inmediato si no hay clave configurada.

    Pensada para validar la configuración al arrancar la CLI/API, en vez de
    descubrir el problema recién en la primera llamada al LLM.
    """
    key = get_api_key()
    if not key:
        raise RuntimeError(
            "Falta DEEPINFRA_API_KEY (o OPENAI_API_KEY) en el entorno o en .env."
        )
    return key


def get_model() -> str:
    """Devuelve el modelo configurado, normalizado para DeepInfra.

    Quita el prefijo ``deepinfra/`` si está presente (formato usado por
    CrewAI/litellm) para que la API directa de DeepInfra lo acepte.
    """
    _load_env_file()
    model = os.getenv("LLM_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL
    return model.removeprefix("deepinfra/")


def chat(
    messages: list[dict[str, str]],
    *,
    temperature: float = 0.7,
    max_tokens: int = 2048,
) -> str:
    """Envía un turno de conversación al LLM y devuelve el texto generado."""
    key = get_api_key()
    if not key:
        raise RuntimeError(
            "Falta DEEPINFRA_API_KEY (o OPENAI_API_KEY) en el entorno."
        )

    payload: dict[str, Any] = {
        "model": get_model(),
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }

    req = urllib.request.Request(
        CHAT_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # noqa: S310 - endpoint público de DeepInfra
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:  # noqa: BLE001
        log.error("llm.chat_error", error=str(e))
        raise RuntimeError(f"Error al llamar al LLM de DeepInfra: {e}") from e

    try:
        return data["choices"][0]["message"]["content"]  # type: ignore[no-any-return]
    except (KeyError, IndexError, TypeError) as e:
        log.error("llm.respuesta_invalida", payload=data)
        raise RuntimeError(f"Respuesta inesperada del LLM: {data}") from e


def prompt(mensaje: str, *, system: str | None = None, **kwargs: Any) -> str:
    """Comodidad: construye los mensajes y llama a ``chat``."""
    messages: list[dict[str, str]] = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": mensaje})
    return chat(messages, **kwargs)
