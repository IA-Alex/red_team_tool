#!/usr/bin/env python
"""CLI del red team (Zotz).

Ejecuta el flujo de red team orquestado con LangGraph contra un objetivo
dentro del alcance autorizado. La CLI es interactiva: pide los datos del
engagement que falten y guarda el informe final a disco.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict

from redteamcrew.graph.state import AgentState
from redteamcrew.graph.workflow import build_workflow
from redteamcrew.utils.logger import get_logger

log = get_logger("cli")

CAMPO_ALIAS = {
    "authorized_scope": ("alcance", "--scope"),
    "engagement_name": ("nombre", "--engagement"),
    "company_name": ("empresa", "--company"),
    "rules_of_engagement": ("reglas", "--rules"),
}

PREGUNTA = {
    "authorized_scope": "Alcance autorizado (dominio/IP)",
    "engagement_name": "Nombre del engagement",
    "company_name": "Empresa objetivo",
    "rules_of_engagement": "Reglas de engagement",
}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="redteamcrew",
        description=(
            "Flujo de red team orquestado con LangGraph. "
            "Los datos que no se pasen por argumentos se piden interactivamente."
        ),
    )
    parser.add_argument(
        "--scope",
        dest="authorized_scope",
        help="Alcance autorizado (dominio o IP)",
    )
    parser.add_argument(
        "--engagement",
        dest="engagement_name",
        help="Nombre del engagement",
    )
    parser.add_argument(
        "--company",
        dest="company_name",
        help="Empresa objetivo",
    )
    parser.add_argument(
        "--rules",
        dest="rules_of_engagement",
        help="Reglas de engagement",
    )
    parser.add_argument(
        "--out",
        default="outputs",
        help="Directorio donde se guarda el informe final (default: outputs)",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="No preguntar interactivamente; usar valores por defecto para lo faltante",
    )
    return parser.parse_args(argv)


def _preguntar(campo: str, args: argparse.Namespace) -> str:
    """Pide interactivamente un dato al operador (con confirmación)."""
    valor = getattr(args, campo, "")
    if valor:
        return valor.strip()

    if args.yes:
        return ""

    etiqueta = PREGUNTA[campo]
    respuesta = input(f"{etiqueta}: ").strip()
    if not respuesta and args.yes:
        return ""
    return respuesta


def _confirmar(inputs: Dict[str, Any]) -> bool:
    """Muestra el resumen del engagement y confirma antes de lanzar."""
    print("\n=== Resumen del engagement ===")
    for campo, valor in inputs.items():
        etiqueta = CAMPO_ALIAS.get(campo, (campo, ""))[0]
        print(f"  {etiqueta}: {valor or '(sin definir)'}")
    print()

    if sys.stdin.isatty():
        resp = input("¿Confirmas y lanzas el flujo? [s/N]: ").strip().lower()
        return resp in ("s", "si", "sí", "y", "yes")

    print("No es una terminal interactiva. Lanzando el flujo...")
    return True


def _guardar_informe(inputs: Dict[str, Any], informe: str, out: Path) -> Path:
    """Persiste el informe final a disco y devuelve su ruta."""
    engagement = (inputs.get("engagement_name") or "engagement").strip()
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in engagement)
    dest = out / safe
    dest.mkdir(parents=True, exist_ok=True)

    archivo = dest / "informe.md"
    archivo.write_text(informe, encoding="utf-8")
    return archivo


def run(argv: list[str] | None = None) -> None:
    """Punto de entrada de la CLI."""
    args = parse_args(argv)

    inputs: Dict[str, Any] = {
        "authorized_scope": _preguntar("authorized_scope", args),
        "engagement_name": _preguntar("engagement_name", args),
        "company_name": _preguntar("company_name", args),
        "rules_of_engagement": _preguntar("rules_of_engagement", args),
    }

    if not inputs["authorized_scope"]:
        log.error("cli.sin_alcance", mensaje="Falta el alcance autorizado")
        print("Error: debes indicar un alcance autorizado (--scope).")
        sys.exit(2)

    if not _confirmar(inputs):
        print("Engagement cancelado por el operador.")
        sys.exit(0)

    initial_state: AgentState = {
        "objetivo": inputs["authorized_scope"],
        "inputs": inputs,
        "hallazgos": [],
        "iteraciones": 0,
        "es_suficiente": False,
        "superficie": "",
        "vulnerabilidades": "",
        "validacion": "",
        "aprobacion": "",
        "rutas": "",
        "revision": "",
        "informe": "",
    }

    log.info("cli.lanzando", scope=inputs["authorized_scope"])
    app = build_workflow()
    final_state = app.invoke(initial_state)

    informe = final_state.get("informe", "(sin informe)")
    out_dir = Path(args.out)
    archivo = _guardar_informe(inputs, informe, out_dir)

    print("\n\n===== INFORME FINAL =====\n")
    print(informe)
    print(f"\nInforme guardado en: {archivo}")


if __name__ == "__main__":
    run()
