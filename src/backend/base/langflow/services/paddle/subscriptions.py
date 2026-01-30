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
from sqlalchemy.orm.attributes import flag_modified
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.services.auth.clerk_utils import (
    get_org_id_from_clerk_payload,
    get_email_from_clerk_payload,
    get_clerk_user_id_from_payload,
    get_paddle_customer_id_from_clerk_payload,
    update_clerk_private_metadata,
)
from langflow.services.database.models.user import User
from langflow.services.paddle.client import get_paddle_client


@dataclass(frozen=True)
class PaddleSubscriptionStatus:
    has_subscription: bool
    subscription_status: Literal["trialing", "active"] | None
    subscription_id: str | None
    trial_end: datetime | None


async def get_paddle_subscription_status(
    *,
    user: User,
    org_id: str,
    session: AsyncSession,
    client: Client | None = None,
) -> PaddleSubscriptionStatus:
    paddle_client = client or get_paddle_client()
    customer_id = _get_paddle_customer_id(user)

    if not customer_id:
        await _create_paddle_customer(paddle_client, user, org_id, session)
        return PaddleSubscriptionStatus(
            has_subscription=False,
            subscription_status=None,
            subscription_id=None,
            trial_end=None,
        )

    subscriptions = await _list_subscriptions(paddle_client, customer_id)
    logger.info(f"Found {subscriptions} subscriptions for user {user.id}")
    return _evaluate_subscriptions(subscriptions)


async def ensure_paddle_subscription_status_for_user(
    *,
    user: User,
    session: AsyncSession,
    client: Client | None = None,
) -> PaddleSubscriptionStatus:
    org_id = get_org_id_from_clerk_payload()
    return await get_paddle_subscription_status(
        user=user,
        org_id=org_id,
        session=session,
        client=client,
    )


def _get_paddle_customer_id(user: User) -> str | None:
    optins = user.optins if isinstance(user.optins, dict) else {}
    customer_id = optins.get("paddle_customer_id")
    if isinstance(customer_id, str) and customer_id.strip():
        return customer_id
    return None


async def _create_paddle_customer(
    client: Client,
    user: User,
    org_id: str,
    session: AsyncSession,
) -> str:
    # 1️⃣ DB first
    optins = user.optins if isinstance(user.optins, dict) else {}
    existing = optins.get("paddle_customer_id")
    if isinstance(existing, str) and existing.strip():
        return existing

    # 2️⃣ Clerk metadata (after JWT refresh)
    clerk_customer_id = get_paddle_customer_id_from_clerk_payload()
    if clerk_customer_id:
        user.optins = {**optins, "paddle_customer_id": clerk_customer_id}
        flag_modified(user, "optins")
        session.add(user)
        await session.commit()
        return clerk_customer_id

    # 3️⃣ Create Paddle customer
    email = get_email_from_clerk_payload()
    clerk_user_id = get_clerk_user_id_from_payload()

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

    paddle_customer_id = customer.id

    user.optins = {**optins, "paddle_customer_id": paddle_customer_id}
    flag_modified(user, "optins")
    session.add(user)
    await session.commit()

    await update_clerk_private_metadata(
        clerk_user_id=clerk_user_id,
        private_metadata={"paddle_customer_id": paddle_customer_id},
    )

    return paddle_customer_id


async def _list_subscriptions(client: Client, customer_id: str) -> list[Any]:
    return await asyncio.to_thread(
        lambda: list(client.subscriptions.list(customer_id=customer_id))
    )


def _evaluate_subscriptions(subscriptions: list[Any]) -> PaddleSubscriptionStatus:
    for subscription in subscriptions:
        status = getattr(subscription, "status", None)
        if status in {"active", "trialing"}:
            return PaddleSubscriptionStatus(
                has_subscription=True,
                subscription_status=status,
                subscription_id=getattr(subscription, "id", None),
                trial_end=_normalize_trial_end(
                    getattr(subscription, "trial_ends_at", None)
                ),
            )
    return PaddleSubscriptionStatus(
        has_subscription=False,
        subscription_status=None,
        subscription_id=None,
        trial_end=None,
    )


def _normalize_trial_end(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None
