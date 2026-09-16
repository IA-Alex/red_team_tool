"""Envoltorios ligeros para herramientas de enumeración especializada."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from redteamcrew.scope import ScopeError, resolve_and_check
from redteamcrew.tools.executor import _run_subprocess
from redteamcrew.utils.logger import get_logger

log = get_logger("enum_tool")

# Timeouts conservadores: sin límite, un objetivo que no cierra la conexión
# (script NSE que espera respuesta, servidor HTTP que cuelga la respuesta)
# bloquea el nodo de análisis indefinidamente, y con un worker de arq que
# procesa jobs en serie, eso puede colgar el pipeline completo de un
# engagement (y los que estén en cola detrás).
_SSH_ENUM_TIMEOUT = 60
_HTTP_ENUM_TIMEOUT = 20

_ACCOUNTS_RE = re.compile(r"Accounts:\s*(.+)")


@dataclass
class EnumResult:
    tool: str
    target: str
    output: str
    usuarios: list[str] = field(default_factory=list)


def _parse_ssh_enum_users(salida: str) -> list[str]:
    """Extrae los nombres de cuenta de la salida de ``ssh-enum-users``.

    Formato típico de nmap:  ``|_  Accounts: root, admin, guest``. Devolver
    una lista estructurada evita que el consumidor (``enum_privs_nodo``) tenga
    que volver a parsear el texto pensado para lectura humana.
    """
    usuarios: list[str] = []
    for linea in salida.splitlines():
        match = _ACCOUNTS_RE.search(linea)
        if not match:
            continue
        usuarios.extend(u.strip() for u in match.group(1).split(",") if u.strip())
    return usuarios


def run_ssh_enum(target: str, authorized_scope: str) -> EnumResult:
    """Enumera usuarios SSH mediante Nmap script."""
    if not resolve_and_check(target, authorized_scope):
        raise ScopeError(f"'{target}' está fuera del alcance autorizado.")

    log.info("enum.ssh", target=target)
    cmd = ["nmap", "-p", "22", "--script", "ssh-enum-users", target]
    try:
        salida = _run_subprocess(cmd, timeout=_SSH_ENUM_TIMEOUT)
    except RuntimeError as e:
        log.warning("enum.ssh_error", target=target, error=str(e))
        return EnumResult("ssh-enum", target, str(e))
    return EnumResult("ssh-enum", target, salida, usuarios=_parse_ssh_enum_users(salida))


def run_http_enum(target_url: str, authorized_scope: str) -> EnumResult:
    """Enumeración HTTP básica (cabeceras, directorios comunes)."""
    host = urlparse(target_url).hostname or target_url
    if not resolve_and_check(host, authorized_scope):
        raise ScopeError(f"'{host}' está fuera del alcance autorizado.")

    log.info("enum.http", target=target_url)
    # Ejemplo conceptual: curl -I (en producción usar ffuf/gobuster ligero)
    cmd = ["curl", "-I", target_url]
    try:
        salida = _run_subprocess(cmd, timeout=_HTTP_ENUM_TIMEOUT)
    except RuntimeError as e:
        log.warning("enum.http_error", target=target_url, error=str(e))
        return EnumResult("http-enum", target_url, str(e))
    return EnumResult("http-enum", target_url, salida)
