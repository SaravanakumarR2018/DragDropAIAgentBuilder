"""Paddle Billing subscription status helpers."""

from __future__ import annotations

import asyncio
import re
from typing import Any
from uuid import UUID

from lfx.log.logger import logger
from paddle_billing import Client  #noqa: TCH002
from paddle_billing.Entities.Shared import CountryCode, CustomData
from paddle_billing.Resources.Customers.Operations import CreateCustomer, UpdateCustomer
from paddle_billing.Resources.Addresses.Operations import CreateAddress

from langflow.services.auth.clerk_metadata_constants import (
    ORGANISATION_CREATED_BY_KEY,
    PADDLE_CUSTOM_DATA_USER_ID_KEY,
    PADDLE_CUSTOMER_ID_KEY,
    PADDLE_SUBSCRIPTION_ID_KEY,
    PADDLE_PLAN_KEY,
    PADDLE_SEATS_KEY,
    PADDLE_SUBSCRIPTION_STATUS_KEY,
    PADDLE_TRIAL_END_KEY,
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
            "has_access": False,
            "subscription_status": None,
            "paddle_subscription_id": None,
            "organisation_created_by": created_by,
        }

    status = await get_subscription_status(subscription_id=sub_id, client=client)
    has_access = status in ACTIVE_SUBSCRIPTION_STATUSES if status else False
    logger.info(f"Subscription {sub_id} - status: {status}, has_access: {has_access}, active_statuses: {ACTIVE_SUBSCRIPTION_STATUSES}")
    return {
        "has_access": has_access,
        "subscription_status": status,
        "paddle_subscription_id": sub_id,
        "organisation_created_by": created_by,
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


async def start_trial_subscription(
    *,
    plan_key: str,
    seats: int,
    country: str,
    postal_code: str,
    client: Client | None = None,
) -> dict[str, Any]:
    if seats < 1:
        msg = "seats must be at least 1"
        raise ValueError(msg)

    normalized_country = _normalize_country_for_paddle(country)
    normalized_postal_code = postal_code.strip()
    if not normalized_postal_code:
        msg = "postal_code is required"
        raise ValueError(msg)

    paddle_client = client or get_paddle_client()
    org_id = get_org_id_from_clerk_payload()
    organisation_created_by = get_clerk_user_id_from_payload()

    subscription_id = await get_paddle_subscription_id_from_clerk_payload()
    if subscription_id:
        msg = "subscription already exists for current user/session"
        raise ValueError(msg)

    customer_id = await ensure_paddle_customer_for_user(client=paddle_client)
    if not customer_id:
        msg = "unable to resolve paddle customer"
        raise ValueError(msg)

    from langflow.services.paddle.provisioning import get_paddle_prices

    price_map = await get_paddle_prices(client=paddle_client)
    price_id = price_map.get(plan_key)
    if not price_id:
        msg = f"no Paddle price mapped for plan_key={plan_key}"
        raise ValueError(msg)

    address_id = await _create_paddle_address_for_customer(
        client=paddle_client,
        customer_id=customer_id,
        country_code=normalized_country,
        postal_code=normalized_postal_code,
    )

    payload = {
        "items": [{"price_id": price_id, "quantity": seats}],
        "customer_id": customer_id,
        "address_id": address_id,
        "status": "billed",
    }

    transaction = await asyncio.to_thread(paddle_client.transactions.create, payload)
    details = _extract_subscription_details_from_transaction(transaction)

    await update_clerk_organization(
        org_id=org_id,
        public_metadata={
            PADDLE_SUBSCRIPTION_ID_KEY: details["subscription_id"],
            ORGANISATION_CREATED_BY_KEY: organisation_created_by,
        },
        max_allowed_members=seats,
    )

    await update_clerk_user_metadata(
        clerk_user_id=organisation_created_by,
        public_metadata={
            PADDLE_SUBSCRIPTION_ID_KEY: details["subscription_id"],
            PADDLE_PLAN_KEY: plan_key,
            PADDLE_SUBSCRIPTION_STATUS_KEY: details["status"],
            PADDLE_TRIAL_END_KEY: details["trial_end"],
            PADDLE_SEATS_KEY: seats,
        },
    )

    return {
        "subscription_id": details["subscription_id"],
        "status": details["status"],
        "trial_end": details["trial_end"],
        "plan_key": plan_key,
        "seats": seats,
    }


def _normalize_country_for_paddle(country: str) -> CountryCode:
    value = country.strip()
    if not value:
        raise ValueError("country is required")

    try:
        import pycountry
        # try uppercase first (for ISO alpha-2)
        result = pycountry.countries.lookup(value.upper())
        iso2 = result.alpha_2.upper()
        logger.info(f"Normalized country '{value}' to ISO2 code: {iso2}")
        return CountryCode(iso2)

    except LookupError:
        raise ValueError(f"invalid or unsupported country: {country}")


def _extract_address_id(address: Any) -> str:
    address_id = getattr(address, "id", None)
    if isinstance(address_id, UUID):
        return str(address_id)
    if isinstance(address_id, str) and address_id.strip():
        return address_id.strip()

    data = _normalize_custom_data(getattr(address, "data", None))
    nested_id = data.get("id") if isinstance(data, dict) else None
    if isinstance(nested_id, UUID):
        return str(nested_id)
    if isinstance(nested_id, str) and nested_id.strip():
        return nested_id.strip()

    msg = "Paddle address response missing id"
    raise ValueError(msg)


async def _create_paddle_address_for_customer(
    *,
    client: Client,
    customer_id: str,
    country_code: CountryCode,
    postal_code: str,
) -> str:

    operation = CreateAddress(
        country_code=country_code,
        postal_code=postal_code,
    )

    address = await asyncio.to_thread(
        client.addresses.create,
        customer_id,
        operation,
    )

    logger.info(f"Created Paddle address for customer {customer_id}: {address}")

    return _extract_address_id(address)


def _extract_subscription_details_from_transaction(transaction: Any) -> dict[str, str]:
    data = _normalize_custom_data(getattr(transaction, "data", None)) or transaction
    if not isinstance(data, dict):
        data = {}

    subscription_id = (
        data.get("subscription_id")
        or _normalize_custom_data(data.get("subscription", None)).get("id")
    )
    status = data.get("status") or _normalize_custom_data(data.get("subscription", None)).get("status")
    trial_end = (
        data.get("next_billed_at")
        or _normalize_custom_data(data.get("subscription", None)).get("next_billed_at")
    )

    if not isinstance(subscription_id, str) or not subscription_id.strip():
        msg = "Paddle transaction response missing subscription_id"
        raise ValueError(msg)

    normalized_status = str(status).strip() if status else "trialing"
    normalized_trial_end = str(trial_end).strip() if trial_end else ""

    return {
        "subscription_id": subscription_id.strip(),
        "status": normalized_status,
        "trial_end": normalized_trial_end,
    }


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

