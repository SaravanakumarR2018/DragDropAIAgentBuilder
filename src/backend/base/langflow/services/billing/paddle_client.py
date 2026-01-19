from __future__ import annotations

import os
from typing import Final

from paddle_billing import Client, Environment, Options
from pydantic import SecretStr

from lfx.log.logger import logger

PADDLE_ENVIRONMENT_ENV_VAR: Final[str] = "PADDLE_ENVIRONMENT"

_paddle_client: Client | None = None


def _resolve_secret(value: SecretStr | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, SecretStr):
        return value.get_secret_value()
    return value


def _select_environment() -> Environment:
    environment_value = os.getenv(PADDLE_ENVIRONMENT_ENV_VAR, "production").strip().lower()
    if environment_value in {"sandbox", "staging", "test"}:
        return Environment.SANDBOX
    return Environment.PRODUCTION


def initialize_paddle_client(api_key: SecretStr | str | None, client_key: SecretStr | str | None) -> Client | None:
    global _paddle_client

    if _paddle_client is not None:
        return _paddle_client

    resolved_api_key = _resolve_secret(api_key)
    if not resolved_api_key:
        logger.warning("Paddle API key is missing; skipping Paddle client initialization.")
        return None

    environment = _select_environment()
    _paddle_client = Client(resolved_api_key, options=Options(environment))

    if not _resolve_secret(client_key):
        logger.warning("Paddle client key is missing; frontend Paddle.js may not initialize.")

    logger.info("Paddle client initialized.")
    return _paddle_client


def get_paddle_client() -> Client | None:
    return _paddle_client
