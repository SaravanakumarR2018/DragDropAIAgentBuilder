"""Paddle Billing client setup."""

from __future__ import annotations

from os import getenv

from paddle_billing import Client

from lfx.log.logger import logger

_paddle_client: Client | None = None


def initialize_paddle_client(api_key: str) -> Client:
    """Initialize and return the Paddle Billing client."""
    global _paddle_client
    if _paddle_client is not None:
        logger.info("Paddle client already initialized, returning existing client.")
        return _paddle_client

    api_key = api_key
    if not api_key:
        msg = "PADDLE_API_KEY must be set to initialize the Paddle Billing client."
        logger.error(msg)
        raise ValueError(msg)
    masked_key = f"{api_key[:4]}...{api_key[-4:]}" if len(api_key) > 8 else "***"
    logger.info("Loaded PADDLE_API_KEY from environment: %s", masked_key)

    _paddle_client = Client(api_key)
    logger.info("Paddle Billing client initialized successfully.")
    return _paddle_client


def get_paddle_client() -> Client:
    """Return the initialized Paddle Billing client."""
    return initialize_paddle_client()