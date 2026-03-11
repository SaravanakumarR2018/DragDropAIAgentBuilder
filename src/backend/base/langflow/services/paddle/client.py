"""Paddle Billing client setup."""

from __future__ import annotations

from lfx.log.logger import logger
from paddle_billing import Client, Environment, Options

from langflow.services.deps import get_settings_service

_paddle_client: Client | None = None

settings_service = get_settings_service()


def initialize_paddle_client(api_key: str) -> Client:
    """Initialize and return the Paddle Billing client."""
    # ruff: noqa: PLW0603
    global _paddle_client
    if _paddle_client is not None:
        logger.info("Paddle client already initialized, returning existing client.")
        return _paddle_client

    if not api_key:
        msg = "PADDLE_API_KEY must be set to initialize the Paddle Billing client."
        logger.error(msg)
        raise ValueError(msg)

    normalized_environment = (
        settings_service.settings.paddle_environment
    ).lower()

    if normalized_environment == "staging":
        _paddle_client = Client(api_key, options=Options(Environment.SANDBOX))
    elif normalized_environment == "prod":
        _paddle_client = Client(api_key)

    logger.info("Paddle Billing client initialized successfully.")
    return _paddle_client


def get_paddle_client() -> Client:
    """Return the initialized Paddle Billing client."""
    return initialize_paddle_client(settings_service.settings.paddle_api_key)

def setup_paddle_billing() -> None:
    """Initialize Paddle billing client and provision plans."""
    if settings_service.settings.paddle_api_key and settings_service.settings.paddle_client_key:
        logger.info("Paddle billing configured; initializing client and provisioning plans.")
        try:
            from langflow.services.paddle.provisioning import provision_paddle_plans

            initialize_paddle_client(settings_service.settings.paddle_api_key)
            provision_paddle_plans()
            logger.info("Paddle billing setup completed successfully.")
        except Exception as exc:
            logger.error(f"Failed to initialize Paddle billing: {exc}")
            raise
    else:
        msg = (
            "Paddle billing env vars missing; set PADDLE_API_KEY and PADDLE_CLIENT_KEY "
            "to enable billing."
        )
        raise RuntimeError(msg)
