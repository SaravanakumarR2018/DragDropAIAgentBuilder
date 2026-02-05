"""Paddle Billing subscription status helpers."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

from lfx.log.logger import logger
from paddle_billing import Client
from paddle_billing.Entities.Shared import CustomData
from paddle_billing.Resources.Customers.Operations import CreateCustomer
from paddle_billing.Resources.Subscriptions.Operations import ListSubscriptions


from langflow.services.auth.clerk_utils import (
    get_org_id_from_clerk_payload,
    get_email_from_clerk_payload,
    get_clerk_user_id_from_payload,
    get_paddle_customer_id_from_clerk_payload,
    update_clerk_public_metadata,
)
from langflow.services.auth.clerk_metadata_constants import (
    PADDLE_CUSTOMER_ID_KEY,
    PADDLE_CUSTOM_DATA_USER_ID_KEY,
    ORG_ID_KEY,
)
from langflow.services.paddle.client import get_paddle_client


async def ensure_paddle_customer_for_user(
    *,
    client: Client | None = None,
) -> str | None:
    """Ensure a Paddle customer exists for the current Clerk user.

    The Clerk JWT is used to obtain the email and clerk user id; callers
    should not pass a `User` instance (e.g., `current_user`).
    """
    paddle_client = client or get_paddle_client()
    customer_id = await _get_paddle_customer_id()
    clerk_user_id = get_clerk_user_id_from_payload()
    logger.info(f"Paddle customer ID for clerk user {clerk_user_id}: {customer_id}")
    if customer_id:
        return customer_id
    logger.info(
        f"No Paddle customer ID found for clerk user {clerk_user_id}, creating new customer"
    )
    customer_id = await _create_paddle_customer_and_update_clerk_metadata(paddle_client, clerk_user_id)
    return customer_id


async def _get_paddle_customer_id() -> str | None:
    logger.info("Retrieving Paddle customer ID from Clerk payload")
    return await get_paddle_customer_id_from_clerk_payload()


async def _create_paddle_customer_and_update_clerk_metadata(
    client: Client,
    clerk_user_id: str,
) -> str:

    # 1️⃣ Create Paddle customer
    email = get_email_from_clerk_payload()
    logger.info(f"Creating Paddle customer for email: {email}")
    logger.info(f"Clerk user ID: {clerk_user_id}")

    customer = await asyncio.to_thread(
        client.customers.create,
        CreateCustomer(
            email=email,
            custom_data=CustomData(
                {
                    PADDLE_CUSTOM_DATA_USER_ID_KEY: str(clerk_user_id),
                }
            ),
        ),
    )
    logger.info(f"Paddle customer creation response: {customer}")

    paddle_customer_id = customer.id

    logger.info(f"Created Paddle customer {paddle_customer_id} for user {clerk_user_id}")
    await update_clerk_public_metadata(
        clerk_user_id=clerk_user_id,
        public_metadata={PADDLE_CUSTOMER_ID_KEY: paddle_customer_id},
    )

    return paddle_customer_id
