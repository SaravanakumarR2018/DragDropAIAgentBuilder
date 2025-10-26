from __future__ import annotations

import signal
from typing import Any, Callable

from langflow.logging.logger import logger

_clerk_debug_logs_enabled = False
_signal_handlers_registered = False


def set_clerk_debug_logs(enabled: bool) -> None:
    """Toggle Clerk authentication debug logging at runtime."""

    global _clerk_debug_logs_enabled
    _clerk_debug_logs_enabled = enabled
    state = "enabled" if enabled else "disabled"
    logger.info("Clerk auth debug logging %s", state)


def is_clerk_debug_logs_enabled() -> bool:
    """Return whether Clerk auth debug logging is enabled."""

    return _clerk_debug_logs_enabled


def clerk_debug_log(message: str, *args: Any, **kwargs: Any) -> None:
    """Log a debug message when Clerk auth debug logging is enabled."""

    if _clerk_debug_logs_enabled:
        logger.info(message, *args, **kwargs)


def _make_handler(enabled: bool) -> Callable[[int, Any], None]:
    def handler(signum: int, frame: Any) -> None:  # noqa: ANN001
        set_clerk_debug_logs(enabled)
        clerk_debug_log(
            "Received signal %s. Clerk auth debug logging %s.",
            signum,
            "enabled" if enabled else "disabled",
        )

    return handler


def register_clerk_debug_signal_handlers() -> None:
    """Register SIGUSR1/SIGUSR2 handlers to toggle runtime debug logging."""

    global _signal_handlers_registered
    if _signal_handlers_registered:
        return

    try:
        signal.signal(signal.SIGUSR1, _make_handler(True))
        signal.signal(signal.SIGUSR2, _make_handler(False))
        _signal_handlers_registered = True
    except (AttributeError, ValueError, OSError) as exc:  # pragma: no cover - platform dependent
        logger.debug("Unable to register Clerk debug logging signal handlers: %s", exc)
