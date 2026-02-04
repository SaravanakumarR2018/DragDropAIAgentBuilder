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
from paddle_billing.Resources.Subscriptions.Operations import (
    ListSubscriptions,
)


from langflow.services.auth.clerk_utils import (
    get_org_id_from_clerk_payload,
    get_email_from_clerk_payload,
    get_clerk_user_id_from_payload,
    get_paddle_customer_id_from_clerk_payload,
    get_paddle_subscription_id_from_clerk_payload,
    get_organisation_created_by_from_clerk_payload,
    update_clerk_public_metadata,
)
from langflow.services.database.models.user import User
from langflow.services.paddle.client import get_paddle_client

ACTIVE_SUBSCRIPTION_STATUSES = {"active", "trialing"}


async def ensure_paddle_customer_for_user(
    *,
    user: User,
    client: Client | None = None,
) -> str | None:
    paddle_client = client or get_paddle_client()
    customer_id = await _get_paddle_customer_id()
    logger.info(f"Paddle customer ID for user {user.id}: {customer_id}")
    if customer_id:
        return customer_id
    logger.info(f"No Paddle customer ID found for user {user.id}, creating new customer")
    org_id = get_org_id_from_clerk_payload()
    customer_id = await _create_paddle_customer(paddle_client, user, org_id)
    return customer_id


async def _get_paddle_customer_id() -> str | None:
    logger.info("Retrieving Paddle customer ID from Clerk payload")
    return await get_paddle_customer_id_from_clerk_payload()


async def _create_paddle_customer(
    client: Client,
    user: User,
    org_id: str,
) -> str:

    # 1️⃣ Create Paddle customer
    email = get_email_from_clerk_payload()
    logger.info(f"Creating Paddle customer for email: {email}")
    clerk_user_id = get_clerk_user_id_from_payload()
    logger.info(f"Clerk user ID: {clerk_user_id}")

    customer = await asyncio.to_thread(
        client.customers.create,
        CreateCustomer(
            email=email,
            custom_data=CustomData(
                {
                    "org_id": org_id,
                    "user_id": str(user.id),
                }
            ),
        ),
    )
    logger.info(f"Paddle customer creation response: {customer}")

    paddle_customer_id = customer.id

    logger.info(f"Created Paddle customer {paddle_customer_id} for user {user.id}")
    await update_clerk_public_metadata(
        clerk_user_id=clerk_user_id,
        public_metadata={"paddle_customer_id": paddle_customer_id},
    )

    return paddle_customer_id


def _find_price_id_for_plan(client: Client, plan_key: str) -> str | None:
    for price in client.prices.list():
        custom_data = getattr(price, "custom_data", None)
        if custom_data and custom_data.get("plan_key") == plan_key:
            return price.id
    return None


async def create_subscription_for_customer(
    *,
    customer_id: str,
    plan_key: str,
    quantity: int,
    org_id: str,
    client: Client | None = None,
) -> Any:
    paddle_client = client or get_paddle_client()
    price_id = await asyncio.to_thread(_find_price_id_for_plan, paddle_client, plan_key)
    if not price_id:
        msg = f"No Paddle price found for plan {plan_key}"
        raise ValueError(msg)

    subscription_payload = {
        "customer_id": customer_id,
        "items": [{"price_id": price_id, "quantity": quantity}],
        "custom_data": CustomData({"org_id": org_id, "plan_key": plan_key}),
    }
    subscription = await asyncio.to_thread(
        paddle_client.subscriptions.create,
        subscription_payload,
    )
    return subscription


async def get_subscription_status(
    *,
    subscription_id: str,
    client: Client | None = None,
) -> str | None:
    paddle_client = client or get_paddle_client()
    if hasattr(paddle_client.subscriptions, "get"):
        subscription = await asyncio.to_thread(
            paddle_client.subscriptions.get, subscription_id
        )
        return getattr(subscription, "status", None)

    list_response = await asyncio.to_thread(
        paddle_client.subscriptions.list,
        ListSubscriptions(id=subscription_id),
    )
    for subscription in list_response:
        return getattr(subscription, "status", None)
    return None


async def has_active_subscription(
    *,
    subscription_id: str | None = None,
    client: Client | None = None,
) -> dict[str, Any]:
    sub_id = subscription_id or await get_paddle_subscription_id_from_clerk_payload()
    created_by = await get_organisation_created_by_from_clerk_payload()
    if not sub_id:
        return {
            "has_access": False,
            "subscription_status": None,
            "paddle_subscription_id": None,
            "organisation_created_by": created_by,
        }

    status = await get_subscription_status(subscription_id=sub_id, client=client)
    has_access = status in ACTIVE_SUBSCRIPTION_STATUSES if status else False
    return {
        "has_access": has_access,
        "subscription_status": status,
        "paddle_subscription_id": sub_id,
        "organisation_created_by": created_by,
    }
