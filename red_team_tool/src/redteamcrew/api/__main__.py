"""Punto de entrada para lanzar el servidor API con uvicorn.

Uso:
    python -m redteamcrew.api
    redteamcrew-api --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import argparse

import uvicorn


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Zotz Red Team API")
    parser.add_argument("--host", default="127.0.0.1", help="Interfaz de escucha")
    parser.add_argument("--port", type=int, default=8000, help="Puerto")
    args = parser.parse_args(argv)

    uvicorn.run("redteamcrew.api.server:app", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
