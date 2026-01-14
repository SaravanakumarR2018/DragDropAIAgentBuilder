from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from paddle_billing import Client

from lfx.log.logger import logger
from lfx.services.settings.base import Settings


@dataclass(frozen=True)
class PaddleCredentials:
    api_key: str
    client_key: str
    environment: str


def _normalize_environment(environment: str) -> str:
    if environment == "prod":
        return "production"
    return "sandbox" if environment == "staging" else environment


@lru_cache(maxsize=2)
def _build_client(environment: str, api_key: str, client_key: str) -> Client:
    normalized_environment = _normalize_environment(environment)
    try:
        return Client(api_key=api_key, environment=normalized_environment, client_token=client_key)
    except TypeError:
        logger.warning("Paddle SDK client_token parameter not supported; initializing without it.")
        return Client(api_key=api_key, environment=normalized_environment)


def get_paddle_client(settings: Settings) -> Client:
    """Return a shared Paddle SDK client configured for the active environment."""
    try:
        api_key, client_key, environment = settings.get_paddle_credentials()
    except ValueError:
        logger.error("Unable to initialize Paddle client due to missing credentials.")
        raise

    return _build_client(environment, api_key, client_key)
