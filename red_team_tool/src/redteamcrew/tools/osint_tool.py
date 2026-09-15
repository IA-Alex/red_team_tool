"""Herramienta OSINT personalizada para Zotz.

Consulta APIs públicas y gratuitas para reconocimiento pasivo de superficie de
ataque, sin requerir claves de API. Todas las fuentes están definidas en
``src/redteamcrew/config/tasks.yaml``:

- Resolución DNS:      https://dns.google/resolve
- Subdominios:         https://api.hackertarget.com/hostsearch
- Certificados (CT):   https://crt.sh
- Fingerprinting IP:   https://internetdb.shodan.io
- CVE por producto:    https://cve.circl.lu/api/search
- Detalle CVE:         https://cve.circl.lu/api/cve
- CISA KEV:            https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- Inteligencia OTX:    https://otx.alienvault.com/api/v1/indicators/domain
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, Type

from crewai.tools import BaseTool
from pydantic import BaseModel, Field


class OsintSearchInput(BaseModel):
    """Esquema de entrada para la herramienta OSINT."""
    query: str = Field(
        ...,
        description=(
            "Objetivo de la consulta. Puede ser: un dominio/IP para reconocimiento, "
            "un producto/versión (ej. 'apache 2.4.49') para buscar CVEs, o "
            "'cisa-kev' para listar CVEs explotados activamente."
        ),
    )
    operation: str = Field(
        default="auto",
        description=(
            "Operación a ejecutar: 'dns', 'subdomains', 'certs', 'ip', "
            "'cve', 'cve_detail', 'cisa_kev', 'otx' o 'auto'. En 'auto' se "
            "deduce según el formato del query."
        ),
    )


class OsintSearchTool(BaseTool):
    """Consulta APIs públicas y gratuitas de inteligencia de código abierto."""

    name: str = "osint_search"
    description: str = (
        "Realiza reconocimiento pasivo y consultas de vulnerabilidades usando "
        "APIs públicas y gratuitas sin requerir API key. Útil para: resolver "
        "DNS, enumerar subdominios, consultar certificados SSL, obtener puertos/"
        "servicios de una IP, buscar CVEs por producto y versión, consultar "
        "CISA KEV y obtener inteligencia de amenazas de OTX AlienVault."
    )
    args_schema: Type[BaseModel] = OsintSearchInput

    _timeout: int = 20

    _IPV4_OCTETS = 4
    _IPV4_MAX = 255

    def _fetch_json(self, url: str) -> dict | list:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Zotz-OSINT/0.1 (red team engagement)"},
        )
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310 - URLs de fuentes públicas definidas
            return json.loads(resp.read().decode("utf-8"))  # type: ignore[no-any-return]

    def _fetch_text(self, url: str) -> str:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Zotz-OSINT/0.1 (red team engagement)"},
        )
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310 - URLs de fuentes públicas definidas
            return resp.read().decode("utf-8", errors="replace")  # type: ignore[no-any-return]

    def _safe_fetch(self, url: str) -> str:
        try:
            return self._fetch_text(url)
        except urllib.error.HTTPError as e:
            return f"HTTP {e.code} al consultar {url}"
        except urllib.error.URLError as e:
            return f"Error de red al consultar {url}: {e.reason}"
        except Exception as e:  # noqa: BLE001
            return f"Error inesperado al consultar {url}: {e}"

    def _op_dns(self, domain: str) -> str:
        registros = []
        for tipo in ("A", "MX", "TXT"):
            url = (
                "https://dns.google/resolve?name="
                + urllib.parse.quote(domain)
                + f"&type={tipo}"
            )
            data = self._safe_fetch(url)
            registros.append(f"--- {tipo} ---\n{data}")
        return "\n".join(registros)

    def _op_subdomains(self, domain: str) -> str:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        return self._safe_fetch(url)

    def _op_certs(self, domain: str) -> str:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        return self._safe_fetch(url)

    def _op_ip(self, ip: str) -> str:
        url = f"https://internetdb.shodan.io/{ip}"
        return self._safe_fetch(url)

    def _op_cve(self, product: str, version: str = "") -> str:
        query = f"{product} {version}".strip()
        url = (
            "https://cve.circl.lu/api/search/"
            + urllib.parse.quote(query, safe="")
        )
        return self._safe_fetch(url)

    def _op_cve_detail(self, cve_id: str) -> str:
        url = f"https://cve.circl.lu/api/cve/{cve_id}"
        return self._safe_fetch(url)

    def _op_cisa_kev(self) -> str:
        url = (
            "https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json"
        )
        return self._safe_fetch(url)

    def _op_otx(self, domain: str) -> str:
        base = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}"
        general = self._safe_fetch(f"{base}/general")
        malware = self._safe_fetch(f"{base}/malware")
        return f"--- general ---\n{general}\n--- malware ---\n{malware}"

    def _is_ip(self, value: str) -> bool:
        partes = value.split(".")
        if len(partes) != self._IPV4_OCTETS:
            return False
        return all(
            p.isdigit() and 0 <= int(p) <= self._IPV4_MAX for p in partes
        )

    def _is_cve(self, value: str) -> bool:
        return value.upper().startswith("CVE-")

    def _run(self, query: str, operation: str = "auto") -> str:
        query = query.strip()
        op = operation.strip().lower()

        if op == "auto":
            op = self._autodetect(query)

        handlers = {
            "dns": lambda: self._op_dns(query),
            "subdomains": lambda: self._op_subdomains(query),
            "certs": lambda: self._op_certs(query),
            "ip": lambda: self._op_ip(query),
            "cve": self._op_cve_from_query(query),
            "cve_detail": lambda: self._op_cve_detail(query),
            "cisa_kev": self._op_cisa_kev,
            "otx": lambda: self._op_otx(query),
        }

        handler = handlers.get(op)
        if handler is None:
            return (
                f"Operación '{operation}' no reconocida. Válidas: dns, "
                "subdomains, certs, ip, cve, cve_detail, cisa_kev, otx."
            )
        return handler()

    def _autodetect(self, query: str) -> str:
        if query.lower() == "cisa-kev":
            return "cisa_kev"
        if self._is_cve(query):
            return "cve_detail"
        if self._is_ip(query):
            return "ip"
        return "dns"

    def _op_cve_from_query(self, query: str) -> Callable[[], str]:
        partes = query.split(maxsplit=1)
        producto = partes[0]
        version = partes[1] if len(partes) > 1 else ""
        return lambda: self._op_cve(producto, version)
