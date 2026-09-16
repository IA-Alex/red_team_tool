"""Análisis estático (AST) nativo para Zotz.

Permite analizar código fuente local sin dependencias externas, utilizando
librerías estándar de Python (ast, re).
"""

from __future__ import annotations

import ast
import os
import re

_SCAN_ROOT_ENV = "REDTEAMCREW_SCAN_ROOT"
_MAX_WALK_DEPTH = 8


class ScanPathError(ValueError):
    """La ruta solicitada no está permitida para análisis estático."""


def _validar_dentro_de_raiz(target_path: str) -> str:
    """Resuelve ``target_path`` y verifica que caiga dentro de ``REDTEAMCREW_SCAN_ROOT``.

    ``scan_ast`` se expone como herramienta invocable (potencialmente por un
    agente LLM), así que no basta con que el llamador ya haya validado la
    ruta antes de invocarla: el propio scanner debe rechazar cualquier ruta
    fuera de la raíz de confianza, incluso si se lo llama directamente.
    """
    root_raw = os.getenv(_SCAN_ROOT_ENV)
    if not root_raw:
        raise ScanPathError(
            f"Análisis estático deshabilitado: {_SCAN_ROOT_ENV} no está configurado."
        )

    root = os.path.realpath(root_raw)
    resuelta = os.path.realpath(target_path)
    if os.path.commonpath([root, resuelta]) != root:
        raise ScanPathError(
            f"La ruta '{target_path}' está fuera de la raíz autorizada ({root})."
        )
    return resuelta


def _listar_py_con_limite(target_path: str) -> list[str]:
    """Lista archivos .py bajo ``target_path``, sin descender más de ``_MAX_WALK_DEPTH``."""
    base_depth = target_path.rstrip(os.sep).count(os.sep)
    encontrados: list[str] = []
    for root, dirs, fs in os.walk(target_path):
        profundidad = root.rstrip(os.sep).count(os.sep) - base_depth
        if profundidad >= _MAX_WALK_DEPTH:
            dirs.clear()
            continue
        encontrados.extend(os.path.join(root, f) for f in fs if f.endswith(".py"))
    return encontrados


def scan_ast(target_path: str) -> str:
    """Analiza un archivo o directorio buscando vulnerabilidades estáticas.

    Busca funciones peligrosas (eval, exec), inyección SQL potencial y secretos
    hardcodeados (regex).

    Args:
        target_path: Ruta del archivo o directorio a analizar. Debe caer
            dentro de la raíz configurada en ``REDTEAMCREW_SCAN_ROOT``.

    Returns:
        Texto con los hallazgos encontrados o un mensaje informativo.
    """
    try:
        target_path = _validar_dentro_de_raiz(target_path)
    except ScanPathError as e:
        return f"Error: {e}"

    if not os.path.exists(target_path):
        return f"Error: La ruta {target_path} no existe."

    if os.path.isfile(target_path):
        files = [target_path]
    else:
        files = _listar_py_con_limite(target_path)

    results: list[str] = []
    for file_path in files:
        results.extend(_scan_file(file_path))

    # Búsqueda de secretos vía regex
    secret_regex = re.compile(
        r"(?i)(api_key|secret|password|token)\s*=\s*['\"]"
        r"([a-zA-Z0-9_\-]{16,})['\"]"
    )
    for file_path in files:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            for match in secret_regex.finditer(content):
                results.append(
                    f"[!] Secreto potencial hardcodeado: {match.group(1)} "
                    f"en {file_path}"
                )
        except OSError as e:
            results.append(f"Error analizando {file_path}: {e}")

    if results:
        return "\n".join(results)
    return "No se encontraron vulnerabilidades críticas mediante análisis estático."


def _scan_file(file_path: str) -> list[str]:
    """Escanea un único archivo buscando vulnerabilidades vía AST."""
    findings: list[str] = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read())

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            # Funciones peligrosas
            if isinstance(node.func, ast.Name) and node.func.id in [
                "eval",
                "exec",
            ]:
                findings.append(
                    f"[!] Función peligrosa encontrada: {node.func.id} "
                    f"en {file_path}:{node.lineno}"
                )

            # Inyección SQL simplificada (ej. cursor.execute("..."))
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "execute"
            ):
                # f-strings o concatenación en el primer argumento
                if len(node.args) > 0 and isinstance(
                    node.args[0], (ast.JoinedStr, ast.BinOp)
                ):
                    findings.append(
                        f"[!] Posible inyección SQL encontrada en "
                        f"{file_path}:{node.lineno}"
                    )
    except Exception as e:  # noqa: BLE001
        findings.append(f"Error analizando {file_path}: {e}")

    return findings
