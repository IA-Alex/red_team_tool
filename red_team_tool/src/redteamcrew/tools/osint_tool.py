"""Funciones OSINT para Zotz.

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
from typing import Callable

_TIMEOUT = 20
_IPV4_OCTETS = 4
_IPV4_MAX = 255

_USER_AGENT = "Zotz-OSINT/0.1 (red team engagement)"


def _fetch_json(url: str) -> dict | list:
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310 - URLs de fuentes públicas definidas
        return json.loads(resp.read().decode("utf-8"))  # type: ignore[no-any-return]


def _fetch_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310 - URLs de fuentes públicas definidas
        return resp.read().decode("utf-8", errors="replace")  # type: ignore[no-any-return]


def _safe_fetch(url: str) -> str:
    try:
        return _fetch_text(url)
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code} al consultar {url}"
    except urllib.error.URLError as e:
        return f"Error de red al consultar {url}: {e.reason}"
    except Exception as e:  # noqa: BLE001
        return f"Error inesperado al consultar {url}: {e}"


def _op_dns(domain: str) -> str:
    registros = []
    for tipo in ("A", "MX", "TXT"):
        url = (
            "https://dns.google/resolve?name="
            + urllib.parse.quote(domain)
            + f"&type={tipo}"
        )
        data = _safe_fetch(url)
        registros.append(f"--- {tipo} ---\n{data}")
    return "\n".join(registros)


def _op_subdomains(domain: str) -> str:
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    return _safe_fetch(url)


def _op_certs(domain: str) -> str:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    return _safe_fetch(url)


def _op_ip(ip: str) -> str:
    url = f"https://internetdb.shodan.io/{ip}"
    return _safe_fetch(url)


def _op_cve(product: str, version: str = "") -> str:
    query = f"{product} {version}".strip()
    url = "https://cve.circl.lu/api/search/" + urllib.parse.quote(query, safe="")
    return _safe_fetch(url)


def _op_cve_detail(cve_id: str) -> str:
    url = f"https://cve.circl.lu/api/cve/{cve_id}"
    return _safe_fetch(url)


def _op_cisa_kev() -> str:
    url = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )
    return _safe_fetch(url)


def _op_otx(domain: str) -> str:
    base = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}"
    general = _safe_fetch(f"{base}/general")
    malware = _safe_fetch(f"{base}/malware")
    return f"--- general ---\n{general}\n--- malware ---\n{malware}"


def _is_ip(value: str) -> bool:
    partes = value.split(".")
    if len(partes) != _IPV4_OCTETS:
        return False
    return all(p.isdigit() and 0 <= int(p) <= _IPV4_MAX for p in partes)


def _is_cve(value: str) -> bool:
    return value.upper().startswith("CVE-")


def _autodetect(query: str) -> str:
    if query.lower() == "cisa-kev":
        return "cisa_kev"
    if _is_cve(query):
        return "cve_detail"
    if _is_ip(query):
        return "ip"
    return "dns"


def _op_cve_from_query(query: str) -> Callable[[], str]:
    partes = query.split(maxsplit=1)
    producto = partes[0]
    version = partes[1] if len(partes) > 1 else ""
    return lambda: _op_cve(producto, version)


def osint_search(query: str, operation: str = "auto") -> str:
    """Realiza una consulta OSINT según el query y la operación indicada.

    Args:
        query: Objetivo de la consulta (dominio, IP, producto/versión o CVE).
        operation: 'dns', 'subdomains', 'certs', 'ip', 'cve', 'cve_detail',
            'cisa_kev', 'otx' o 'auto' (deducción por formato).

    Returns:
        Resultado en texto plano de la consulta.
    """
    query = query.strip()
    op = operation.strip().lower()

    if op == "auto":
        op = _autodetect(query)

    handlers = {
        "dns": lambda: _op_dns(query),
        "subdomains": lambda: _op_subdomains(query),
        "certs": lambda: _op_certs(query),
        "ip": lambda: _op_ip(query),
        "cve": _op_cve_from_query(query),
        "cve_detail": lambda: _op_cve_detail(query),
        "cisa_kev": _op_cisa_kev,
        "otx": lambda: _op_otx(query),
    }

    handler = handlers.get(op)
    if handler is None:
        return (
            f"Operación '{operation}' no reconocida. Válidas: dns, "
            "subdomains, certs, ip, cve, cve_detail, cisa_kev, otx."
        )
    return handler()
