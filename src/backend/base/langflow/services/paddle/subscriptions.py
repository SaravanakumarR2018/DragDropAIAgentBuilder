"""Paddle Billing subscription status helpers."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
import re
from typing import Any, Literal

from lfx.log.logger import logger
from paddle_billing import Client
from paddle_billing.Entities.Shared import CustomData
from paddle_billing.Resources.Customers.Operations import CreateCustomer, UpdateCustomer
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

_PADDLE_CUSTOMER_ID_RE = re.compile(r"(ctm_[a-z0-9]+)", re.IGNORECASE)


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


def _extract_customer_id_from_error(exc: Exception) -> str | None:
    match = _PADDLE_CUSTOMER_ID_RE.search(str(exc))
    return match.group(1) if match else None


async def _create_paddle_customer_and_update_clerk_metadata(
    client: Client,
    clerk_user_id: str,
) -> str:

    # 1️⃣ Create Paddle customer
    email = get_email_from_clerk_payload()
    logger.info(f"Creating Paddle customer for email: {email}")
    logger.info(f"Clerk user ID: {clerk_user_id}")

    try:
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
    except Exception as exc:  # noqa: BLE001
        customer_id = _extract_customer_id_from_error(exc)

        if not customer_id:
            if not _is_customer_already_exists_error(exc):
                raise

            logger.info(
                "Paddle customer already exists for email %s; resolving existing customer.",
                email,
            )
            customer = await _find_existing_paddle_customer(
                client=client,
                email=email,
                clerk_user_id=clerk_user_id,
            )
            if customer is None:
                logger.exception("Unable to resolve existing Paddle customer for email %s.", email)
                raise
        else:
            logger.info(
                "Paddle reports existing customer %s for email %s",
                customer_id,
                email,
            )
            customer = await asyncio.to_thread(client.customers.get, customer_id)

        await _sync_paddle_customer_metadata(
            client=client,
            customer=customer,
            clerk_user_id=clerk_user_id,
        )

        await update_clerk_public_metadata(
            clerk_user_id=clerk_user_id,
            public_metadata={PADDLE_CUSTOMER_ID_KEY: customer.id},
        )
        return customer.id

    paddle_customer_id = customer.id

    logger.info(f"Created Paddle customer {paddle_customer_id} for user {clerk_user_id}")
    await update_clerk_public_metadata(
        clerk_user_id=clerk_user_id,
        public_metadata={PADDLE_CUSTOMER_ID_KEY: paddle_customer_id},
    )

    return paddle_customer_id


def _is_customer_already_exists_error(exc: Exception) -> bool:
    message = str(exc).lower()
    return (
        "customer already exists" in message
        or ("already exists" in message and "customer" in message)
        or ("customer email conflicts" in message)
        or ("email conflicts" in message and "customer" in message)
    )


async def _find_existing_paddle_customer(
    *,
    client: Client,
    email: str,
    clerk_user_id: str,
) -> Any | None:
    def _list_customers() -> list[Any]:
        return list(client.customers.list())

    customers = await asyncio.to_thread(_list_customers)
    email_normalized = email.lower().strip()

    for customer in customers:
        custom_data = getattr(customer, "custom_data", None) or {}
        if str(custom_data.get(PADDLE_CUSTOM_DATA_USER_ID_KEY, "")).strip() == str(clerk_user_id):
            return customer

    for customer in customers:
        customer_email = getattr(customer, "email", "")
        if isinstance(customer_email, str) and customer_email.lower().strip() == email_normalized:
            return customer

    return None


async def _sync_paddle_customer_metadata(
    *,
    client: Client,
    customer: Any,
    clerk_user_id: str,
) -> None:
    existing_custom_data = dict(getattr(customer, "custom_data", None) or {})
    if str(existing_custom_data.get(PADDLE_CUSTOM_DATA_USER_ID_KEY, "")).strip() == str(clerk_user_id):
        return

    updated_custom_data = dict(existing_custom_data)
    updated_custom_data[PADDLE_CUSTOM_DATA_USER_ID_KEY] = str(clerk_user_id)
    await asyncio.to_thread(
        client.customers.update,
        customer.id,
        UpdateCustomer(custom_data=CustomData(updated_custom_data)),
    )
