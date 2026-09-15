import structlog

# Configuración básica para Zotz-core
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.JSONRenderer(),
    ],
    logger_factory=structlog.PrintLoggerFactory(),
)


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(f"zotz-core.{name}")  # type: ignore[no-any-return]

