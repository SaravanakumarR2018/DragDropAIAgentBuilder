from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request, status

from langflow.api.utils import DbSession
from langflow.services.billing.access_control import update_user_from_stripe_payload

router = APIRouter(prefix="/billing/stripe", tags=["Billing"])

STRIPE_SIGNATURE_TOLERANCE_SECONDS = 300


def _parse_stripe_signature(signature_header: str) -> tuple[str | None, list[str]]:
    timestamp = None
    signatures: list[str] = []
    for part in signature_header.split(","):
        key, _, value = part.partition("=")
        if key == "t":
            timestamp = value
        elif key == "v1":
            signatures.append(value)
    return timestamp, signatures


def _verify_stripe_signature(payload: bytes, signature_header: str, secret: str) -> None:
    timestamp, signatures = _parse_stripe_signature(signature_header)
    if not timestamp or not signatures:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Stripe signature header")

    try:
        timestamp_int = int(timestamp)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Stripe signature timestamp") from exc

    if abs(time.time() - timestamp_int) > STRIPE_SIGNATURE_TOLERANCE_SECONDS:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Stripe signature timestamp out of tolerance")

    signed_payload = f"{timestamp}.{payload.decode('utf-8')}".encode("utf-8")
    expected_signature = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()

    if not any(hmac.compare_digest(expected_signature, provided) for provided in signatures):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Stripe signature")


def _get_webhook_secret() -> str:
    secret = os.getenv("STRIPE_WEBHOOK_SECRET")
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Stripe webhook secret not configured",
        )
    return secret


def _extract_user_id_from_subscription(subscription: dict[str, Any]) -> str | None:
    metadata = subscription.get("metadata")
    if isinstance(metadata, dict):
        user_id = metadata.get("user_id")
        if isinstance(user_id, str):
            return user_id
    return None


async def _handle_checkout_completed(session: DbSession, payload: dict[str, Any]) -> None:
    user_id = payload.get("client_reference_id")
    updates = {
        "stripe_customer_id": payload.get("customer"),
        "stripe_subscription_id": payload.get("subscription"),
        "stripe_subscription_status": "active",
    }
    await update_user_from_stripe_payload(session, user_id, updates)


async def _handle_subscription_event(session: DbSession, payload: dict[str, Any]) -> None:
    user_id = _extract_user_id_from_subscription(payload)
    updates = {
        "stripe_customer_id": payload.get("customer"),
        "stripe_subscription_id": payload.get("id"),
        "stripe_subscription_status": payload.get("status"),
        "stripe_current_period_end": payload.get("current_period_end"),
        "stripe_cancel_at_period_end": payload.get("cancel_at_period_end"),
    }
    await update_user_from_stripe_payload(session, user_id, updates)


@router.post("/webhook")
async def stripe_webhook(
    request: Request,
    session: DbSession,
    stripe_signature: str | None = Header(default=None, alias="Stripe-Signature"),
) -> dict[str, bool]:
    if stripe_signature is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing Stripe signature header")

    payload = await request.body()
    _verify_stripe_signature(payload, stripe_signature, _get_webhook_secret())

    event = json.loads(payload)
    event_type = event.get("type")
    event_data = event.get("data", {}).get("object", {})

    if event_type == "checkout.session.completed":
        await _handle_checkout_completed(session, event_data)
    elif event_type in {
        "customer.subscription.created",
        "customer.subscription.updated",
        "customer.subscription.deleted",
    }:
        await _handle_subscription_event(session, event_data)

    return {"received": True}
