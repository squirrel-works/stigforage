"""structlog configuration. Logs go to stderr so stdout stays clean for results."""

from __future__ import annotations

import logging
import sys

import structlog

__all__ = ["configure", "get_logger"]


def configure(verbosity: int = 0) -> None:
    """Configure structlog. verbosity: -1 warnings only, 0 info, 1+ debug."""
    level = logging.WARNING if verbosity < 0 else logging.DEBUG if verbosity > 0 else logging.INFO
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="%H:%M:%S", utc=False),
            structlog.dev.ConsoleRenderer(colors=False),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=False,
    )


def get_logger() -> structlog.typing.FilteringBoundLogger:
    return structlog.get_logger()  # type: ignore[no-any-return]
