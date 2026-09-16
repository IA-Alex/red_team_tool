"""Ejecución de herramientas activas (nmap, nuclei) contra el alcance autorizado.

A diferencia de ``tools/osint_tool.py`` (consultas pasivas a APIs públicas), este
módulo lanza subprocesos reales que envían tráfico al objetivo. Por eso:

1. Nunca ejecuta nada sin pasar primero por ``scope.resolve_and_check`` — el
   chokepoint técnico de alcance. Si el objetivo no verifica, se lanza
   ``ScopeError`` y el subproceso jamás se invoca.
2. Respeta el kill-switch ``REDTEAMCREW_ACTIVE_RECON=0``: con esa variable, las
   funciones no hacen nada (devuelven listas/estructuras vacías) — permite
   desplegar la API en modo solo-pasivo.
3. Usa flags conservadores por defecto (sin scripts NSE agresivos, sin
   plantillas de nuclei destructivas/fuzzing) — el objetivo de esta fase es
   verificar hallazgos, no maximizar agresividad.
"""

from __future__ import annotations

import json
import os
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

from redteamcrew.scope import ScopeError, resolve_and_check
from redteamcrew.utils.logger import get_logger

log = get_logger("executor")

_ACTIVE_RECON_ENV = "REDTEAMCREW_ACTIVE_RECON"
_STEALTH_MODE_ENV = "REDTEAMCREW_STEALTH_MODE"
_NMAP_TIMEOUT = 180
_NUCLEI_TIMEOUT = 300
_MAX_OUTPUT_BYTES = 10 * 1024 * 1024  # 10 MiB: cota razonable para XML/JSONL de nmap/nuclei


def _activo_habilitado() -> bool:
    return os.getenv(_ACTIVE_RECON_ENV, "1").strip() != "0"


def _es_sigiloso() -> bool:
    return os.getenv(_STEALTH_MODE_ENV, "0").strip() == "1"


def _run_subprocess(cmd: list[str], timeout: int) -> str:
    """Ejecuta un comando como lista de argumentos (nunca shell=True)."""
    try:
        resultado = subprocess.run(  # noqa: S603 - cmd es una lista fija, no shell
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as e:
        raise RuntimeError(f"Herramienta no encontrada: {cmd[0]}") from e
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"Timeout ejecutando: {' '.join(cmd)}") from e

    salida = resultado.stdout
    if len(salida.encode("utf-8", errors="ignore")) > _MAX_OUTPUT_BYTES:
        log.warning("executor.output_truncado", comando=cmd[0], bytes=len(salida))
        salida = salida[: _MAX_OUTPUT_BYTES]
    return salida


@dataclass
class Puerto:
    numero: int
    protocolo: str
    servicio: str
    version: str = ""


@dataclass
class NmapResult:
    host: str
    puertos: list[Puerto] = field(default_factory=list)


def run_nmap(target: str, authorized_scope: str) -> NmapResult:
    """Escaneo activo conservador (top-100 puertos TCP connect, sin NSE)."""
    if not _activo_habilitado():
        log.warning("executor.recon_activo_deshabilitado", target=target)
        return NmapResult(host=target)

    if not resolve_and_check(target, authorized_scope):
        raise ScopeError(f"'{target}' está fuera del alcance autorizado.")

    log.info("executor.nmap", target=target)
    cmd = ["nmap", "-sT", "-Pn", "--top-ports", "100", "-oX", "-", target]
    if _es_sigiloso():
        cmd.extend(["--max-rate", "10", "--scan-delay", "1s"])
    salida = _run_subprocess(cmd, timeout=_NMAP_TIMEOUT)
    return _parse_nmap_xml(target, salida)


def _parse_nmap_xml(target: str, xml_text: str) -> NmapResult:
    resultado = NmapResult(host=target)
    if not xml_text.strip():
        return resultado
    try:
        root = ET.fromstring(xml_text)  # noqa: S314 - XML propio generado por nmap local
    except ET.ParseError:
        log.error("executor.nmap_xml_invalido", target=target)
        return resultado

    for host_el in root.findall("host"):
        for port_el in host_el.findall("./ports/port"):
            estado = port_el.find("state")
            if estado is None or estado.get("state") != "open":
                continue
            servicio_el = port_el.find("service")
            servicio = servicio_el.get("name", "") if servicio_el is not None else ""
            version = servicio_el.get("product", "") if servicio_el is not None else ""
            resultado.puertos.append(
                Puerto(
                    numero=int(port_el.get("portid", "0")),
                    protocolo=port_el.get("protocol", "tcp"),
                    servicio=servicio,
                    version=version,
                )
            )
    return resultado


@dataclass
class PocResult:
    success: bool
    output: str


@dataclass
class NucleiFinding:
    host: str
    plantilla: str
    severidad: str
    nombre: str
    evidencia: str

def run_poc(target: str, plantilla: str, authorized_scope: str) -> PocResult:
    """Ejecuta una PoC de forma controlada.
    
    Restricciones: 
    - Se ejecuta solo con herramientas permitidas (nuclei como PoC).
    - Timeout estricto.
    - Sin privilegios elevados (simulado mediante ejecución sin sudo/cargas peligrosas).
    """
    if not _activo_habilitado():
        log.warning("executor.poc_deshabilitado", target=target)
        return PocResult(success=False, output="PoC deshabilitada")

    if not resolve_and_check(target, authorized_scope):
        raise ScopeError(f"'{target}' está fuera del alcance autorizado.")

    log.info("executor.run_poc", target=target, plantilla=plantilla)
    
    # Ejemplo: usar nuclei en modo de explotación para la plantilla específica
    cmd = [
        "nuclei",
        "-target", target,
        "-templates", plantilla,
        "-jsonl",
        "-silent",
        "-severity", "critical,high", # Solo permitir severidad alta/critica
    ]
    
    salida = _run_subprocess(cmd, timeout=_NUCLEI_TIMEOUT)
    
    # Análisis simple de éxito (ajustar según formato de salida de tool)
    success = "critical" in salida.lower() or "high" in salida.lower()
    return PocResult(success=success, output=salida)


def run_nuclei(target_host: str, authorized_scope: str, target_url: str | None = None) -> list[NucleiFinding]:
    """Escaneo de vulnerabilidades con nuclei, excluyendo plantillas destructivas."""
    if not _activo_habilitado():
        log.warning("executor.recon_activo_deshabilitado", target=target_host)
        return []

    if not resolve_and_check(target_host, authorized_scope):
        raise ScopeError(f"'{target_host}' está fuera del alcance autorizado.")

    target = target_url or target_host
    log.info("executor.nuclei", target=target)
    cmd = [
        "nuclei",
        "-target", target,
        "-jsonl",
        "-severity", "info,low,medium,high,critical",
        "-exclude-tags", "dos,fuzz",
        "-silent",
    ]
    if _es_sigiloso():
        cmd.extend(["-rate-limit", "5", "-delay", "1s"])
    salida = _run_subprocess(cmd, timeout=_NUCLEI_TIMEOUT)
    return _parse_nuclei_jsonl(salida)


def _parse_nuclei_jsonl(jsonl_text: str) -> list[NucleiFinding]:
    hallazgos: list[NucleiFinding] = []
    for cruda in jsonl_text.splitlines():
        linea = cruda.strip()
        if not linea:
            continue
        try:
            data: dict[str, Any] = json.loads(linea)
        except json.JSONDecodeError:
            continue
        info = data.get("info", {})
        hallazgos.append(
            NucleiFinding(
                host=data.get("host", ""),
                plantilla=data.get("template-id", ""),
                severidad=info.get("severity", "unknown"),
                nombre=info.get("name", ""),
                evidencia=data.get("matched-at", ""),
            )
        )
    return hallazgos
