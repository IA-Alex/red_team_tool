"""Pruebas unitarias del worker arq (consumo del stream LangGraph + persistencia)."""

from __future__ import annotations

import json
from typing import Any, AsyncIterator

import pytest

import redteamcrew.worker as w
from redteamcrew.api import store


class FakeWorkflow:
    """Simula el grafo LangGraph con un flujo determinista de fases."""

    def __init__(
        self, nodos: list[str], hosts: list[dict[str, Any]] | None = None
    ) -> None:
        self._nodos = nodos
        self._hosts = hosts or []

    async def astream(
        self, entrada: Any, *, config: Any = None, stream_mode: list[str]
    ) -> AsyncIterator[tuple[str, Any]]:
        del entrada, config, stream_mode
        estado: dict[str, Any] = {
            "informe": "",
            "hosts": self._hosts,
            "hallazgos_verificados": [
                {
                    "host": "example.com",
                    "herramienta": "nuclei",
                    "severidad": "high",
                    "titulo": "Cabecera de seguridad ausente",
                    "evidencia": "http://example.com",
                }
            ],
        }
        for nodo in self._nodos:
            yield ("updates", {nodo: {}})
            estado["informe"] = f"informe de {nodo}"
            yield ("values", dict(estado))


class FakeFailingWorkflow:
    """Simula un grafo que produce hallazgos reales y luego falla (p. ej. un
    timeout del LLM en una fase posterior a recon/análisis)."""

    async def astream(
        self, entrada: Any, *, config: Any = None, stream_mode: list[str]
    ) -> AsyncIterator[tuple[str, Any]]:
        del entrada, config, stream_mode
        estado: dict[str, Any] = {
            "informe": "",
            "hosts": [{"host": "example.com", "ip": "", "puertos": []}],
            "hallazgos_verificados": [
                {
                    "host": "example.com",
                    "herramienta": "nuclei",
                    "severidad": "high",
                    "titulo": "Cabecera de seguridad ausente",
                    "evidencia": "http://example.com",
                }
            ],
        }
        yield ("updates", {"reconocimiento": {}})
        yield ("values", dict(estado))
        yield ("updates", {"analisis": {}})
        yield ("values", dict(estado))
        raise RuntimeError("Error al llamar al LLM de DeepInfra: timeout")


class FakeInterruptWorkflow:
    """Simula un grafo que se pausa por aprobación humana."""

    async def astream(
        self, entrada: Any, *, config: Any = None, stream_mode: list[str]
    ) -> AsyncIterator[tuple[str, Any]]:
        del entrada, config, stream_mode
        interrupcion = type(
            "Interrupt", (), {"value": {"tipo": "aprobacion_humana"}}
        )()
        yield ("updates", {"reconocimiento": {}})
        yield ("values", {"informe": ""})
        yield ("updates", {"__interrupt__": (interrupcion,)})


class FakeRedisCtx:
    """Simula ``ctx["redis"]`` (cliente arq/redis) capturando lo publicado."""

    def __init__(self) -> None:
        self.publicados: list[tuple[str, dict[str, str]]] = []

    async def xadd(
        self,
        clave: str,
        campos: dict[str, str],
        maxlen: int | None = None,
        approximate: bool = False,
    ) -> None:
        self.publicados.append((clave, dict(campos)))

    async def expire(self, clave: str, ttl: int) -> None:
        del clave, ttl


def _inputs_json() -> str:
    return json.dumps(
        {
            "authorized_scope": "example.com",
            "engagement_name": "Test",
            "company_name": "Acme",
            "rules_of_engagement": "",
        }
    )


@pytest.fixture(autouse=True)
def _sin_llm_ni_disco(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(store, "obtener", lambda eid: {"inputs": _inputs_json()})
    monkeypatch.setattr(store, "actualizar", lambda *a, **k: None)
    monkeypatch.setattr(store, "agregar_host", lambda *a, **k: None)
    monkeypatch.setattr(store, "agregar_hallazgo", lambda *a, **k: None)


@pytest.mark.asyncio
async def test_ejecutar_engagement_publica_fases_y_completa(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nodos = [
        "reconocimiento",
        "analisis",
        "validacion",
        "aprobacion",
        "simulacion",
        "revision",
        "informe",
    ]
    monkeypatch.setattr(w, "_obtener_app", lambda: FakeWorkflow(nodos))
    ctx: dict[str, Any] = {"redis": FakeRedisCtx()}

    await w.ejecutar_engagement(ctx, "eng1")

    tipos = [campos["type"] for _, campos in ctx["redis"].publicados]
    assert tipos == ["fase"] * len(nodos) + ["completado"]


@pytest.mark.asyncio
async def test_ejecutar_engagement_persiste_hosts_y_hallazgos(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hosts_persistidos: list[dict[str, Any]] = []
    hallazgos_persistidos: list[dict[str, Any]] = []
    monkeypatch.setattr(
        store,
        "agregar_host",
        lambda eid, host, **k: hosts_persistidos.append({"host": host, **k}),
    )
    monkeypatch.setattr(
        store,
        "agregar_hallazgo",
        lambda eid, **k: hallazgos_persistidos.append(k),
    )
    host_descubierto = {"host": "example.com", "ip": "", "puertos": []}
    monkeypatch.setattr(
        w,
        "_obtener_app",
        lambda: FakeWorkflow(["reconocimiento", "informe"], hosts=[host_descubierto]),
    )
    ctx: dict[str, Any] = {"redis": FakeRedisCtx()}

    await w.ejecutar_engagement(ctx, "eng1")

    assert hosts_persistidos == [{**host_descubierto, "descubierto_via": "nmap"}]
    assert hallazgos_persistidos[0]["herramienta"] == "nuclei"
    assert hallazgos_persistidos[0]["origen"] == "herramienta"


@pytest.mark.asyncio
async def test_ejecutar_engagement_persiste_hallazgos_pese_a_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hosts_persistidos: list[dict[str, Any]] = []
    hallazgos_persistidos: list[dict[str, Any]] = []
    llamadas_status: list[str] = []
    monkeypatch.setattr(
        store,
        "agregar_host",
        lambda eid, host, **k: hosts_persistidos.append({"host": host, **k}),
    )
    monkeypatch.setattr(
        store,
        "agregar_hallazgo",
        lambda eid, **k: hallazgos_persistidos.append(k),
    )
    monkeypatch.setattr(
        store,
        "actualizar",
        lambda eid, **k: llamadas_status.append(k.get("status", "")),
    )
    monkeypatch.setattr(w, "_obtener_app", FakeFailingWorkflow)
    ctx: dict[str, Any] = {"redis": FakeRedisCtx()}

    await w.ejecutar_engagement(ctx, "eng1")

    assert hosts_persistidos, "hosts descubiertos antes del fallo deben persistirse"
    assert hallazgos_persistidos, "hallazgos antes del fallo deben persistirse"
    assert llamadas_status == ["error"]
    tipos = [campos["type"] for _, campos in ctx["redis"].publicados]
    assert tipos[-1] == "error"


@pytest.mark.asyncio
async def test_ejecutar_engagement_pausa_por_aprobacion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(w, "_obtener_app", FakeInterruptWorkflow)
    llamadas_status: list[str] = []
    monkeypatch.setattr(
        store,
        "actualizar",
        lambda eid, **k: llamadas_status.append(k.get("status", "")),
    )
    ctx: dict[str, Any] = {"redis": FakeRedisCtx()}

    await w.ejecutar_engagement(ctx, "eng1")

    tipos = [campos["type"] for _, campos in ctx["redis"].publicados]
    assert tipos == ["fase", "aprobacion_requerida"]
    assert "esperando_aprobacion" in llamadas_status


@pytest.mark.asyncio
async def test_ejecutar_engagement_inexistente(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(store, "obtener", lambda eid: None)
    ctx: dict[str, Any] = {"redis": FakeRedisCtx()}

    await w.ejecutar_engagement(ctx, "no-existe")

    assert ctx["redis"].publicados == []
