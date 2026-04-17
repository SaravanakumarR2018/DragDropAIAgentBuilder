"""Paddle Billing subscription status helpers."""

from __future__ import annotations

import asyncio
from http.client import HTTPException
import re
from typing import Callable, Any, Awaitable
import random

from lfx.log.logger import logger
from paddle_billing import Client  #noqa: TCH002
from paddle_billing.Entities.Shared import CustomData
from paddle_billing.Resources.Customers.Operations import CreateCustomer, UpdateCustomer
from paddle_billing.Resources.Subscriptions.Operations import ListSubscriptions, CancelSubscription, UpdateSubscription
from paddle_billing.Entities.Subscriptions import SubscriptionEffectiveFrom, SubscriptionProrationBillingMode
from paddle_billing.Resources.Subscriptions.Operations.Update import SubscriptionUpdateItem
from paddle_billing.Resources.Subscriptions.Operations import PreviewUpdateSubscription

from langflow.services.auth.clerk_metadata_constants import (
    ORGANISATION_CREATED_BY,
    ORGANISATION_CREATED_BY_KEY,
    PADDLE_CUSTOM_DATA_ORG_ID_KEY,
    PADDLE_CUSTOM_DATA_USER_ID_KEY,
    PADDLE_CUSTOMER_ID_KEY,
    PADDLE_SUBSCRIPTION_ID,
    PADDLE_SUBSCRIPTION_ID_KEY,
    HAS_ACCESS_KEY,
    SUBSCRIPTION_STATUS_KEY,
    SUBSCRIPTION_PLAN_KEY,
    NEXT_BILLED_AT_KEY,
    CURRENT_PERIOD_END_KEY,
    CURRENT_PERIOD_START_KEY,
    CANCEL_SCHEDULED_KEY,
    SUBSCRIPTION_SEATS_KEY,

)
from langflow.services.auth.clerk_utils import (
    get_clerk_user_id_from_payload,
    get_email_from_clerk_payload,
    get_org_id_from_clerk_payload,
    get_organisation_created_by_from_clerk_payload,
    get_paddle_customer_id_from_clerk_payload,
    get_paddle_subscription_id_from_clerk_payload,
    update_clerk_organization,
    update_clerk_user_metadata,
)
from langflow.services.paddle.client import get_paddle_client

_PADDLE_CUSTOMER_ID_RE = re.compile(r"(ctm_[a-z0-9]+)", re.IGNORECASE)

ACTIVE_SUBSCRIPTION_STATUSES = {"active", "trialing"}

async def _ensure_admin_user() -> None:
    clerk_current_user_id = get_clerk_user_id_from_payload()
    organization_created_by = await get_organisation_created_by_from_clerk_payload()
    if not organization_created_by or organization_created_by.strip() != clerk_current_user_id.strip():
        logger.info(f"User {clerk_current_user_id} is not the organization creator, denying subscription change")
        raise HTTPException(status_code=403, detail="Only the organization creator can change the subscription")

def _get_enabled_plan_monthly_price_map() -> dict[str, int]:
    from langflow.services.paddle.provisioning import _load_plan_config

    plan_price_map: dict[str, int] = {}
    for plan in _load_plan_config().get("plans", []):
        if not isinstance(plan, dict):
            continue
        paddle = plan.get("paddle")
        if not isinstance(paddle, dict) or not paddle.get("enabled"):
            continue

        plan_key = paddle.get("plan_key")
        monthly_price_usd_cents = paddle.get("monthly_price_usd_cents")
        if isinstance(plan_key, str) and isinstance(monthly_price_usd_cents, int):
            plan_price_map[plan_key] = monthly_price_usd_cents

    return plan_price_map


async def _get_plan_key_for_price(
    *,
    price_id: str,
    client: Client,
) -> str | None:
    price = await asyncio.to_thread(
        client.prices.get,
        price_id,
    )

    price_custom_data = _normalize_custom_data(getattr(price, "custom_data", None))
    plan_key = price_custom_data.get("plan_key")
    return str(plan_key) if plan_key is not None else None


async def get_subscription_status(
    *,
    subscription_id: str,
    client: Client | None = None,
) -> str | None:
    paddle_client = client or get_paddle_client()

    try:
        subscription = await asyncio.to_thread(
            paddle_client.subscriptions.get,
            subscription_id,
        )
        status = getattr(subscription, "status", None)
        if status:
            status = str(status).lower()
        logger.info(f"Subscription {subscription_id} status: {status}")
        return status #noqa: TRY300

    except Exception as e:
        logger.info(f"Error retrieving subscription {subscription_id}: {e}")
        raise


async def has_active_subscription(
    *,
    subscription_id: str | None = None,
    client: Client | None = None,
) -> dict[str, Any]:
    logger.info(f"Checking active subscription: subscription_id={subscription_id}")
    sub_id = subscription_id or await get_paddle_subscription_id_from_clerk_payload()
    created_by = await get_organisation_created_by_from_clerk_payload()
    if not sub_id:
        logger.info("No subscription ID found, denying access")
        return {
            HAS_ACCESS_KEY: False,
            SUBSCRIPTION_STATUS_KEY: None,
            SUBSCRIPTION_PLAN_KEY: None,
            PADDLE_SUBSCRIPTION_ID: None,
            ORGANISATION_CREATED_BY: created_by,
            NEXT_BILLED_AT_KEY: None,
            CURRENT_PERIOD_END_KEY: None,
            CURRENT_PERIOD_START_KEY: None,
            CANCEL_SCHEDULED_KEY: False,
            SUBSCRIPTION_SEATS_KEY: None,
        }

    paddle_client = client or get_paddle_client()
    subscription = await asyncio.to_thread(
        paddle_client.subscriptions.get,
        sub_id,
    )

    status = getattr(subscription, "status", None)
    if status:
        status = str(status).lower()
    has_access = status in ACTIVE_SUBSCRIPTION_STATUSES if status else False
    subscription_custom_data = _normalize_custom_data(
        getattr(subscription, "custom_data", None)
    )
    plan_key = subscription_custom_data.get("plan_key")
    if plan_key is not None:
        plan_key = str(plan_key)

    next_billed_at = getattr(subscription, "next_billed_at", None)

    current_period = getattr(subscription, "current_billing_period", None)
    current_period_start = None
    current_period_end = None
    if current_period:
        current_period_start = getattr(current_period, "starts_at", None)
        current_period_end = getattr(current_period, "ends_at", None)

    seats = None
    items = getattr(subscription, "items", None)
    if items:
        first_item = items[0]
        quantity = getattr(first_item, "quantity", None)
        if quantity is not None:
            seats = int(quantity)

    scheduled_change = getattr(subscription, "scheduled_change", None)
    cancel_scheduled = False
    if scheduled_change:
        action = getattr(scheduled_change, "action", None)
        cancel_scheduled = str(action).lower() == "cancel"

    logger.info(
        f"Subscription {sub_id} - status: {status}, "
        f"has_access: {has_access}, next_billed_at: {next_billed_at}, "
        f"cancel_scheduled: {cancel_scheduled}"
    )

    return {
        HAS_ACCESS_KEY: has_access,
        SUBSCRIPTION_STATUS_KEY: status,
        SUBSCRIPTION_PLAN_KEY: plan_key,
        PADDLE_SUBSCRIPTION_ID: sub_id,
        ORGANISATION_CREATED_BY: created_by,
        NEXT_BILLED_AT_KEY: next_billed_at,
        CURRENT_PERIOD_END_KEY: current_period_end,
        CURRENT_PERIOD_START_KEY: current_period_start,
        CANCEL_SCHEDULED_KEY: cancel_scheduled,
        SUBSCRIPTION_SEATS_KEY: seats,
    }


async def update_org_billing_metadata(
    *,
    org_id: str,
    subscription_id: str,
    organisation_created_by: str,
    seats: int,
) -> None:
    logger.info(f"Updating org billing metadata for org {org_id}: subscription_id={subscription_id}, seats={seats}")
    await update_clerk_organization(
        org_id=org_id,
        public_metadata={
            PADDLE_SUBSCRIPTION_ID_KEY: subscription_id,
            ORGANISATION_CREATED_BY_KEY: organisation_created_by,
        },
        max_allowed_members=seats,
    )
    logger.info(f"Successfully updated org billing metadata for org {org_id}")


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
    except Exception as exc:
        customer_id = None
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
            try:
                customer = await asyncio.to_thread(client.customers.get, customer_id)
            except Exception as exc:
                logger.exception(
                    "Failed to retrieve existing Paddle customer with ID %s for clerk user %s.",
                    customer_id,
                    clerk_user_id,
                )
                raise

        await _sync_paddle_customer_metadata(
            client=client,
            customer=customer,
            clerk_user_id=clerk_user_id,
        )

        await update_clerk_user_metadata(
            clerk_user_id=clerk_user_id,
            public_metadata={PADDLE_CUSTOMER_ID_KEY: customer.id},
        )
        return customer.id

    paddle_customer_id = customer.id

    logger.info(f"Created Paddle customer {paddle_customer_id} for user {clerk_user_id}")
    await update_clerk_user_metadata(
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

def _normalize_custom_data(raw_custom_data: Any) -> dict[str, Any]:
    if raw_custom_data is None:
        return {}
    if isinstance(raw_custom_data, dict):
        return raw_custom_data

    data = getattr(raw_custom_data, "data", None)
    if isinstance(data, dict):
        return data

    try:
        return dict(raw_custom_data)
    except (TypeError, ValueError):
        return {}


async def _find_existing_paddle_customer(
    *,
    client: Client,
    email: str,
    clerk_user_id: str,
) -> Any | None:
    def _find_customer() -> Any | None:
        candidate_by_email: Any | None = None
        collection: Any | None = client.customers.list()
        email_normalized = email.lower().strip()
        logger.info(f"Searching for existing Paddle customer by clerk_user_id: {clerk_user_id}, email: {email}")

        while collection:
            for customer in collection:
                custom_data = _normalize_custom_data(getattr(customer, "custom_data", None))
                if str(custom_data.get(PADDLE_CUSTOM_DATA_USER_ID_KEY, "")).strip() == str(
                    clerk_user_id
                ):
                    return customer

                customer_email = getattr(customer, "email", "")
                if (
                    candidate_by_email is None
                    and isinstance(customer_email, str)
                    and customer_email.lower().strip() == email_normalized
                ):
                    candidate_by_email = customer

            paginator = getattr(collection, "paginator", None)
            next_page = getattr(paginator, "next", None) if paginator else None
            if not callable(next_page):
                break
            try:
                collection = next_page()
            except Exception:  # noqa: BLE001
                break
        return candidate_by_email

    return await asyncio.to_thread(_find_customer)


async def _sync_paddle_customer_metadata(
    *,
    client: Client,
    customer: Any,
    clerk_user_id: str,
) -> None:
    # Safely extract the custom data dict from the SDK object
    raw_custom_data = getattr(customer, "custom_data", None)

    if raw_custom_data is None:
        existing_custom_data = {}
    elif isinstance(raw_custom_data, dict):
        existing_custom_data = raw_custom_data
    else:
        # Extract the internal dict from the custom data object
        existing_custom_data = dict(raw_custom_data.data)

    # If metadata already matches, no need to update
    if str(existing_custom_data.get(PADDLE_CUSTOM_DATA_USER_ID_KEY, "")).strip() == str(clerk_user_id):
        return

    # Prepare updated data
    updated_custom_data = dict(existing_custom_data)
    updated_custom_data[PADDLE_CUSTOM_DATA_USER_ID_KEY] = str(clerk_user_id)

    # Send update request via Paddle API
    try:
        await asyncio.to_thread(
            client.customers.update,
            customer.id,
            UpdateCustomer(custom_data=CustomData(updated_custom_data)),
        )
    except Exception:
        logger.exception(
            "Failed to sync Paddle customer metadata for customer %s and clerk user %s.",
            customer.id,
            clerk_user_id,
        )
        raise

async def get_subscriptions_by_customer_id(
    *,
    customer_id: str,
    client: Client | None = None,
) -> list[dict]:

    paddle_client = client or get_paddle_client()

    def _fetch():
        return paddle_client.subscriptions.list(
            ListSubscriptions(customer_ids=[customer_id])
        )

    collection = await asyncio.to_thread(_fetch)

    subscriptions = []

    while collection:
        for sub in collection:
            custom_data = _normalize_custom_data(getattr(sub, "custom_data", None))
            subscriptions.append({
                "id": sub.id,
                "status": str(getattr(sub, "status", "")).lower(),
                "customer_id": getattr(sub, "customer_id", None),
                 "org_id": custom_data.get(PADDLE_CUSTOM_DATA_ORG_ID_KEY),
            })

        paginator = getattr(collection, "paginator", None)
        next_page = getattr(paginator, "next", None) if paginator else None

        if not callable(next_page):
            break

        try:
            collection = next_page()
        except Exception:
            break

    return subscriptions

def pick_active_subscription(
    subscriptions: list[dict],
    *,
    org_id: str | None = None,
) -> str | None:
    if org_id:
        for sub in subscriptions:
            status = str(sub.get("status", "")).lower()
            if status in ACTIVE_SUBSCRIPTION_STATUSES and str(sub.get("org_id", "")).strip() == org_id:
                return sub["id"]
    return None

async def fetch_active_subscription(customer_id, org_id):
    subs = await get_subscriptions_by_customer_id(customer_id=customer_id)
    active_id = pick_active_subscription(subs, org_id=org_id)

    if not active_id:
        raise ValueError("No active subscription yet")

    return active_id, subs

async def retry_with_backoff(
    func: Callable[[], Awaitable[Any]],
    retries: int = 3,
    base_delay: float = 2,
    max_delay: float = 10,
    jitter: bool = True,
    retry_exceptions: tuple = (Exception,),
) -> Any:
    last_exception = None

    for attempt in range(retries):
        try:
            return await func()

        except retry_exceptions as e:
            last_exception = e

            delay = min(base_delay * (2 ** attempt), max_delay)

            if jitter:
                delay += random.uniform(0, 0.5)

            logger.info(
                "Retry %s/%s failed. Retrying in %.2fs",
                attempt + 1,
                retries,
                delay
            )
            await asyncio.sleep(delay)

    raise last_exception


async def cancel_subscription(
    *,
    subscription_id: str,
    effective_from_immediately: bool = False,
    client: Client | None = None,
):
    """
    Cancel a Paddle subscription.

    Args:
        subscription_id: Paddle subscription ID (sub_xxx)
        effective_from_immediately: 
            True  -> cancel immediately
            False -> cancel at next billing period (default)
    """
    paddle_client = client or get_paddle_client()

    # Map boolean -> Paddle enum
    effective_from = (
        SubscriptionEffectiveFrom.IMMEDIATELY
        if effective_from_immediately
        else SubscriptionEffectiveFrom.NEXT_BILLING_PERIOD
    )

    operation = CancelSubscription(
        effective_from=effective_from
    )

    try:
        subscription = await asyncio.to_thread(
            paddle_client.subscriptions.cancel,
            subscription_id,
            operation,
        )

        logger.info(
            f"Cancelled subscription {subscription_id} "
            f"(effective_from={effective_from})"
        )

        return {
            "subscription_id": subscription_id,
            "status": getattr(subscription, "status", None),
            "effective_from": str(effective_from),
        }

    except Exception as e:
        logger.exception(f"Error cancelling subscription {subscription_id}: {e}")
        raise


async def _build_updated_items(
    *,
    subscription,
    new_price_id: str | None,
    new_quantity: int | None,
):
    main_plan_key = _normalize_custom_data(
        getattr(subscription, "custom_data", None)
    ).get("plan_key")

    paddle_client = get_paddle_client()

    main_price_id = None

    for item in subscription.items:
        price_plan_key = await _get_plan_key_for_price(
            price_id=item.price.id,
            client=paddle_client,
        )
        if price_plan_key == main_plan_key:
            main_price_id = item.price.id
            break

    updated_items = []

    for item in subscription.items:
        price_id = item.price.id
        quantity = item.quantity

        if new_price_id is not None and price_id == main_price_id:
            price_id = new_price_id
            if new_quantity is not None:
                quantity = new_quantity

        elif new_price_id is None and new_quantity is not None and price_id == main_price_id:
            quantity = new_quantity

        updated_items.append(
            SubscriptionUpdateItem(
                price_id=price_id,
                quantity=quantity,
            )
        )

    return updated_items


async def _merge_custom_data(
    *,
    subscription,
    new_plan_key: str | None,
    org_id: str | None,
):
    existing = _normalize_custom_data(
        getattr(subscription, "custom_data", None)
    )

    merged = dict(existing)

    if new_plan_key is not None:
        merged["plan_key"] = new_plan_key

    if org_id is not None:
        merged[PADDLE_CUSTOM_DATA_ORG_ID_KEY] = org_id

    return merged


async def update_subscription(
    *,
    subscription_id: str,
    new_price_id: str | None = None,
    new_quantity: int | None = None,
    client: Client | None = None,
):
    paddle_client = client or get_paddle_client()

    org_id = get_org_id_from_clerk_payload()

    subscription = await asyncio.to_thread(
        paddle_client.subscriptions.get,
        subscription_id,
    )

    status = str(getattr(subscription, "status", "")).lower()

    current_items = getattr(subscription, "items", [])
    if not current_items:
        raise ValueError("No subscription items found")

    current_price_id = current_items[0].price.id

    new_plan_key = None
    if new_price_id:
        new_plan_key = await _get_plan_key_for_price(
            price_id=new_price_id,
            client=paddle_client,
        )

    current_custom_data = _normalize_custom_data(
        getattr(subscription, "custom_data", None)
    )

    current_plan_key = current_custom_data.get("plan_key")
    if current_plan_key is not None:
        current_plan_key = str(current_plan_key)

    plan_price_map = _get_enabled_plan_monthly_price_map()

    is_upgrade = False
    if (
        isinstance(current_plan_key, str)
        and isinstance(new_plan_key, str)
        and current_plan_key in plan_price_map
        and new_plan_key in plan_price_map
    ):
        is_upgrade = plan_price_map[new_plan_key] > plan_price_map[current_plan_key]

    if is_upgrade:
        if status == "trialing":
            proration_mode = SubscriptionProrationBillingMode.DoNotBill
        else:
            proration_mode = SubscriptionProrationBillingMode.ProratedImmediately
    else:
        proration_mode = SubscriptionProrationBillingMode.DoNotBill

    items = await _build_updated_items(
        subscription=subscription,
        new_price_id=new_price_id,
        new_quantity=new_quantity,
    )

    merged_custom_data = await _merge_custom_data(
        subscription=subscription,
        new_plan_key=new_plan_key or current_plan_key,
        org_id=org_id,
    )

    operation = UpdateSubscription(
        items=items,
        proration_billing_mode=proration_mode,
        custom_data=CustomData(merged_custom_data),
    )

    updated = await asyncio.to_thread(
        paddle_client.subscriptions.update,
        subscription_id,
        operation,
    )

    return {
        "subscription_id": subscription_id,
        "status": getattr(updated, "status", None),
        "price_id": new_price_id or current_price_id,
        "quantity": new_quantity,
        "proration_mode": str(proration_mode),
    }

async def update_subscription_plan(
    *,
    subscription_id: str,
    new_price_id: str,
    quantity: int,
):
    return await update_subscription(
        subscription_id=subscription_id,
        new_price_id=new_price_id,
        new_quantity=quantity,
    )

async def update_subscription_seats(
    *,
    subscription_id: str,
    new_quantity: int,
):
    return await update_subscription(
        subscription_id=subscription_id,
        new_quantity=new_quantity,
    )

async def preview_subscription_update(
    *,
    subscription_id: str,
    new_price_id: str | None,
    new_quantity: int,
):
    paddle_client = get_paddle_client()

    subscription = await asyncio.to_thread(
        paddle_client.subscriptions.get,
        subscription_id,
    )

    items = await _build_updated_items(
        subscription=subscription,
        new_price_id=new_price_id,
        new_quantity=new_quantity,
    )

    operation = PreviewUpdateSubscription(
        items=[
            SubscriptionUpdateItem(
                price_id=item.price_id,
                quantity=item.quantity,
            )
            for item in items
        ],
        proration_billing_mode=SubscriptionProrationBillingMode.ProratedImmediately,
    )

    preview = await asyncio.to_thread(
        paddle_client.subscriptions.preview_update,
        subscription_id,
        operation,
    )

    return {
        "immediate_transaction": getattr(preview, "immediate_transaction", None),
        "next_transaction": getattr(preview, "next_transaction", None),
        "update_summary": getattr(preview, "update_summary", None),
    }