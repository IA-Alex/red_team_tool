"""Validación del alcance autorizado de un engagement.

El campo ``authorized_scope`` es la garantía legal/técnica de un engagement de
red team: solo debe aceptar dominios, direcciones IP o rangos CIDR. Nunca debe
poder interpretarse como una ruta de sistema de archivos (evita que se use,
directa o indirectamente, para leer el disco del servidor) ni como texto libre
sin forma reconocible de objetivo.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import unicodedata

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)

_MAX_TARGETS = 20


class ScopeError(ValueError):
    """El alcance autorizado no tiene una forma válida de objetivo."""


def _is_valid_target(token: str) -> bool:
    """Un único objetivo es válido si es un dominio, una IP o un CIDR."""
    token = token.strip()
    if not token:
        return False
    try:
        ipaddress.ip_network(token, strict=False)
        return True
    except ValueError:
        pass

    # Normaliza a Unicode NFKC antes de exigir IDNA: bloquea homoglifos y
    # formas compatibles (ej. dígitos de ancho completo) que, sin normalizar,
    # podrían colarse por la regex ASCII de abajo o interpretarse distinto
    # entre el operador y el resolver DNS real.
    try:
        normalizado = unicodedata.normalize("NFKC", token)
        ascii_domain = normalizado.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return False
    return bool(_DOMAIN_RE.match(ascii_domain))


def validate_scope(raw: str) -> str:
    """Valida el alcance autorizado (uno o varios objetivos separados por coma).

    Lanza ``ScopeError`` si algún objetivo no es un dominio/IP/CIDR válido, por
    ejemplo si es una ruta de filesystem (``/etc/passwd``, ``.``, ``C:\\...``).
    """
    raw = raw.strip()
    if not raw:
        raise ScopeError("El alcance autorizado no puede estar vacío.")

    objetivos = [t.strip() for t in raw.split(",") if t.strip()]
    if not objetivos:
        raise ScopeError("El alcance autorizado no puede estar vacío.")
    if len(objetivos) > _MAX_TARGETS:
        raise ScopeError(f"Demasiados objetivos en el alcance (máx {_MAX_TARGETS}).")

    invalidos = [t for t in objetivos if not _is_valid_target(t)]
    if invalidos:
        raise ScopeError(
            "Objetivos inválidos en el alcance autorizado (deben ser dominio, "
            f"IP o CIDR): {', '.join(invalidos)}"
        )
    return ", ".join(objetivos)


_IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def _split_scope(authorized_scope: str) -> tuple[list[_IPNetwork], list[str]]:
    """Separa el alcance ya validado en redes IP/CIDR y dominios (minúsculas)."""
    networks: list[_IPNetwork] = []
    domains: list[str] = []
    for token in (t.strip() for t in authorized_scope.split(",")):
        if not token:
            continue
        try:
            networks.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            domains.append(token.lower())
    return networks, domains


def resolve_and_check(target: str, authorized_scope: str) -> bool:
    """Verifica que ``target`` (host concreto a atacar) caiga dentro del alcance.

    A diferencia de ``validate_scope`` (que solo comprueba el *formato* del
    string que introduce el operador), esta función es el chokepoint técnico
    que debe llamarse justo antes de ejecutar cualquier herramienta activa
    (nmap, nuclei, ...) contra un objetivo concreto — que puede ser un
    subdominio descubierto en recon, no literalmente el string de
    ``authorized_scope``. Sin verificación positiva aquí, no hay ejecución.
    """
    target = target.strip()
    if not target:
        return False

    networks, domains = _split_scope(authorized_scope)

    def _ip_en_scope(ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        return any(ip in net for net in networks)

    # ¿El propio target ya es una IP?
    try:
        ipaddress.ip_address(target)
        return _ip_en_scope(target)
    except ValueError:
        pass

    # ¿Es el dominio del alcance o un subdominio de alguno de ellos?
    target_lower = target.lower()
    if any(target_lower == d or target_lower.endswith(f".{d}") for d in domains):
        return True

    # Último recurso: resolver el hostname y comprobar la IP contra los CIDR
    # del alcance (cubre el caso de un subdominio descubierto que resuelve
    # dentro de un rango IP autorizado explícitamente).
    if not networks:
        return False
    try:
        direcciones = {str(info[4][0]) for info in socket.getaddrinfo(target, None)}
    except socket.gaierror:
        return False
    return any(_ip_en_scope(addr) for addr in direcciones)
