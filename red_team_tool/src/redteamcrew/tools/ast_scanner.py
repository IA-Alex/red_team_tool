"""Análisis estático (AST) nativo para Zotz.

Permite analizar código fuente local sin dependencias externas, utilizando
librerías estándar de Python (ast, re).
"""

from __future__ import annotations

import ast
import os
import re


def scan_ast(target_path: str) -> str:
    """Analiza un archivo o directorio buscando vulnerabilidades estáticas.

    Busca funciones peligrosas (eval, exec), inyección SQL potencial y secretos
    hardcodeados (regex).

    Args:
        target_path: Ruta del archivo o directorio a analizar.

    Returns:
        Texto con los hallazgos encontrados o un mensaje informativo.
    """
    if not os.path.exists(target_path):
        return f"Error: La ruta {target_path} no existe."

    if os.path.isfile(target_path):
        files = [target_path]
    else:
        files = [
            os.path.join(root, f)
            for root, _, fs in os.walk(target_path)
            for f in fs
            if f.endswith(".py")
        ]

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
