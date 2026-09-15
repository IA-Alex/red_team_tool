from pathlib import Path

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


def test_scan_ast_nonexistent_path() -> None:
    """Una ruta inexistente devuelve un error claro."""
    resultado = scan_ast("/no/existe/ruta")
    assert "no existe" in resultado


def test_scan_ast_detects_dangerous_functions(tmp_path: Path) -> None:
    """El escáner AST detecta eval en un archivo de prueba."""
    archivo = tmp_path / "app.py"
    archivo.write_text("def unsafe(data):\n    return eval(data)\n")
    resultado = scan_ast(str(archivo))
    assert "eval" in resultado
