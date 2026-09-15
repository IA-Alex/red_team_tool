
from redteamcrew.tools.osint_tool import OsintSearchTool


def test_osint_tool_name():
    """The tool exposes the expected identifier."""
    tool = OsintSearchTool()
    assert tool.name == "osint_search"


def test_osint_tool_schema():
    """The tool has the correct input schema."""
    tool = OsintSearchTool()
    assert tool.args_schema.__name__ == "OsintSearchInput"


def test_osint_tool_auto_detects_ip():
    """An IPv4 query without explicit operation should map to the 'ip' op."""
    tool = OsintSearchTool()
    assert tool._is_ip("8.8.8.8") is True
    assert tool._is_ip("example.com") is False


def test_osint_tool_auto_detects_cve():
    """A CVE-xxxx string should map to the 'cve_detail' op."""
    tool = OsintSearchTool()
    assert tool._is_cve("CVE-2021-44228") is True


def test_osint_tool_unknown_operation():
    """An invalid operation returns a helpful message."""
    tool = OsintSearchTool()
    result = tool._run("anything", operation="not_real")
    assert "no reconocida" in result
