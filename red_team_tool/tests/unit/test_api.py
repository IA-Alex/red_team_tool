"""Pruebas unitarias del servidor API (capa HTTP: creación, auth, relay SSE)."""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from redteamcrew.api import server

client = TestClient(server.app)

HTTP_OK = 200
HTTP_UNAUTHORIZED = 401
HTTP_NOT_FOUND = 404
HTTP_CONFLICT = 409
HTTP_UNPROCESSABLE = 422
HTTP_TOO_MANY_REQUESTS = 429


def _inputs() -> dict[str, str]:
    return {
        "authorized_scope": "example.com",
        "engagement_name": "Test",
        "company_name": "Acme",
        "rules_of_engagement": "",
    }


class _FakePipeline:
    """Simula un pipeline de redis.asyncio sobre un dict en memoria de proceso.

    El rate limit real vive en un sorted set de Redis (necesario para que
    funcione con varias réplicas de la API); estas pruebas no levantan un
    Redis real, así que se simula el subconjunto de comandos que usa
    ``_verificar_rate_limit`` (zremrangebyscore/zcard/zadd/expire).
    """

    def __init__(self, store: dict[str, dict[str, float]]) -> None:
        self._store = store
        self._ops: list[tuple[str, tuple[Any, ...]]] = []

    def zremrangebyscore(self, key: str, min_: float, max_: float) -> "_FakePipeline":
        self._ops.append(("zremrangebyscore", (key, min_, max_)))
        return self

    def zcard(self, key: str) -> "_FakePipeline":
        self._ops.append(("zcard", (key,)))
        return self

    def zadd(self, key: str, mapping: dict[str, float]) -> "_FakePipeline":
        self._ops.append(("zadd", (key, mapping)))
        return self

    def expire(self, key: str, seconds: int) -> "_FakePipeline":
        self._ops.append(("expire", (key, seconds)))
        return self

    async def execute(self) -> list[Any]:
        resultados: list[Any] = []
        for op, args in self._ops:
            if op == "zremrangebyscore":
                key, min_, max_ = args
                zset = self._store.setdefault(key, {})
                for miembro in [m for m, s in zset.items() if min_ <= s <= max_]:
                    del zset[miembro]
                resultados.append(None)
            elif op == "zcard":
                (key,) = args
                resultados.append(len(self._store.get(key, {})))
            elif op == "zadd":
                key, mapping = args
                self._store.setdefault(key, {}).update(mapping)
                resultados.append(len(mapping))
            elif op == "expire":
                resultados.append(True)
        self._ops = []
        return resultados

    async def __aenter__(self) -> "_FakePipeline":
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False


class _FakeRatelimitRedis:
    def __init__(self) -> None:
        self._store: dict[str, dict[str, float]] = {}

    def pipeline(self, transaction: bool = True) -> _FakePipeline:
        del transaction
        return _FakePipeline(self._store)


@pytest.fixture(autouse=True)
def _sin_infra(monkeypatch: pytest.MonkeyPatch) -> None:
    """Evita tocar SQLite/Redis reales en las pruebas de la capa HTTP."""
    monkeypatch.setattr(server.store, "crear", lambda *a, **k: None)
    monkeypatch.setattr(server.store, "actualizar", lambda *a, **k: None)

    fake_redis = _FakeRatelimitRedis()

    async def _obtener_pool_fake() -> _FakeRatelimitRedis:
        return fake_redis

    monkeypatch.setattr(server, "_obtener_pool", _obtener_pool_fake)

    async def _encolar_noop(eng: Any) -> None:
        del eng

    async def _encolar_resume_noop(
        engagement_id: str, decision: dict[str, Any]
    ) -> None:
        del engagement_id, decision

    monkeypatch.setattr(server, "_encolar", _encolar_noop)
    monkeypatch.setattr(server, "_encolar_resume", _encolar_resume_noop)


def test_crear_engagement_encola_el_trabajo(monkeypatch: pytest.MonkeyPatch) -> None:
    llamadas: list[str] = []

    async def _encolar_spy(eng: Any) -> None:
        llamadas.append(eng.id)

    monkeypatch.setattr(server, "_encolar", _encolar_spy)

    r = client.post("/api/engagements", json=_inputs())

    assert r.status_code == HTTP_OK
    assert llamadas == [r.json()["id"]]


def test_crear_engagement_rechaza_scope_invalido() -> None:
    payload = _inputs()
    payload["authorized_scope"] = "/etc/passwd"

    r = client.post("/api/engagements", json=payload)

    assert r.status_code == HTTP_UNPROCESSABLE


def test_crear_engagement_exige_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDTEAMCREW_API_KEY", "s3cr3t")

    sin_key = client.post("/api/engagements", json=_inputs())
    assert sin_key.status_code == HTTP_UNAUTHORIZED

    con_key = client.post(
        "/api/engagements", json=_inputs(), headers={"X-API-Key": "s3cr3t"}
    )
    assert con_key.status_code == HTTP_OK


def test_crear_engagement_rate_limit() -> None:
    for _ in range(5):
        r = client.post("/api/engagements", json=_inputs())
        assert r.status_code == HTTP_OK

    limitado = client.post("/api/engagements", json=_inputs())
    assert limitado.status_code == HTTP_TOO_MANY_REQUESTS


def test_engagement_inexistente_404(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server.store, "obtener", lambda eid: None)

    r = client.get("/api/engagements/no-existe/informe.md")

    assert r.status_code == HTTP_NOT_FOUND


def test_informe_409_mientras_corre(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        server.store,
        "obtener",
        lambda eid: {
            "id": eid,
            "inputs": json.dumps(_inputs()),
            "status": "running",
            "error": None,
            "informe_md": "",
            "informe_html": "",
        },
    )

    r = client.get("/api/engagements/eng1/informe.md")

    assert r.status_code == HTTP_CONFLICT


def test_aprobar_engagement_encola_reanudacion(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        server.store,
        "obtener",
        lambda eid: {
            "id": eid,
            "inputs": json.dumps(_inputs()),
            "status": "esperando_aprobacion",
            "error": None,
            "informe_md": "",
            "informe_html": "",
        },
    )
    llamadas: list[tuple[str, dict[str, Any]]] = []

    async def _resume_spy(engagement_id: str, decision: dict[str, Any]) -> None:
        llamadas.append((engagement_id, decision))

    monkeypatch.setattr(server, "_encolar_resume", _resume_spy)

    r = client.post(
        "/api/engagements/eng1/approve",
        json={"aprobado": True, "comentario": "ok"},
    )

    assert r.status_code == HTTP_OK
    assert llamadas == [("eng1", {"aprobado": True, "comentario": "ok"})]


def test_aprobar_engagement_409_no_pendiente(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        server.store,
        "obtener",
        lambda eid: {
            "id": eid,
            "inputs": json.dumps(_inputs()),
            "status": "running",
            "error": None,
            "informe_md": "",
            "informe_html": "",
        },
    )

    r = client.post(
        "/api/engagements/eng1/approve",
        json={"aprobado": True, "comentario": ""},
    )

    assert r.status_code == HTTP_CONFLICT


class _FakeRedisStream:
    """Simula el cliente redis.asyncio usado por ``_sse_generator``."""

    def __init__(self, eventos: list[tuple[str, dict[str, str]]]) -> None:
        self._eventos = eventos
        self._i = 0

    async def xread(
        self,
        streams: dict[str, str],
        block: int | None = None,
        count: int | None = None,
    ) -> list[tuple[str, list[tuple[str, dict[str, str]]]]]:
        if self._i >= len(self._eventos):
            return []
        clave = next(iter(streams))
        lote = [self._eventos[self._i]]
        self._i += 1
        return [(clave, lote)]

    async def aclose(self) -> None:
        pass


@pytest.mark.asyncio
async def test_sse_generator_retransmite(monkeypatch: pytest.MonkeyPatch) -> None:
    eventos = [
        ("1-1", {"type": "fase", "data": "reconocimiento"}),
        ("2-1", {"type": "fase", "data": "informe"}),
        ("3-1", {"type": "completado", "data": "ok"}),
    ]
    fake = _FakeRedisStream(eventos)
    monkeypatch.setattr(server.redis_asyncio, "from_url", lambda *a, **k: fake)

    chunks = [c async for c in server._sse_generator("eng1")]
    texto = "".join(chunks)

    assert texto.startswith("event: conectado")
    assert "event: fase" in texto
    assert texto.rstrip().endswith('event: completado\ndata: {"data": "ok"}')
