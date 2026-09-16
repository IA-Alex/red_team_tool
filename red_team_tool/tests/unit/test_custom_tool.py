from pathlib import Path

import pytest

from redteamcrew.tools.ast_scanner import scan_ast
from redteamcrew.tools.osint_tool import osint_search


def test_osint_auto_detects_ip() -> None:
    """Un query IPv4 sin operación explícita se resuelve a la operación 'ip'."""
    resultado = osint_search("8.8.8.8")
    # No lanza y devuelve contenido (puede ser datos o un error de red controlado)
    assert isinstance(resultado, str)
    assert "8.8.8.8" in resultado or "Error" in resultado


def test_osint_unknown_operation() -> None:
    """Una operación inválida devuelve un mensaje útil."""
    resultado = osint_search("anything", operation="not_real")
    assert "no reconocida" in resultado


def test_scan_ast_requiere_scan_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Sin REDTEAMCREW_SCAN_ROOT configurado, el escaneo se rechaza."""
    monkeypatch.delenv("REDTEAMCREW_SCAN_ROOT", raising=False)
    resultado = scan_ast(str(tmp_path))
    assert "deshabilitado" in resultado


def test_scan_ast_rechaza_ruta_fuera_de_la_raiz(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Una ruta fuera de REDTEAMCREW_SCAN_ROOT se rechaza aunque exista."""
    raiz = tmp_path / "raiz"
    raiz.mkdir()
    fuera = tmp_path / "fuera"
    fuera.mkdir()
    monkeypatch.setenv("REDTEAMCREW_SCAN_ROOT", str(raiz))
    resultado = scan_ast(str(fuera))
    assert "fuera de la raíz autorizada" in resultado


def test_scan_ast_nonexistent_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Una ruta inexistente dentro de la raíz devuelve un error claro."""
    monkeypatch.setenv("REDTEAMCREW_SCAN_ROOT", str(tmp_path))
    resultado = scan_ast(str(tmp_path / "no_existe"))
    assert "no existe" in resultado


def test_scan_ast_detects_dangerous_functions(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """El escáner AST detecta eval en un archivo de prueba dentro de la raíz."""
    monkeypatch.setenv("REDTEAMCREW_SCAN_ROOT", str(tmp_path))
    archivo = tmp_path / "app.py"
    archivo.write_text("def unsafe(data):\n    return eval(data)\n")
    resultado = scan_ast(str(archivo))
    assert "eval" in resultado
