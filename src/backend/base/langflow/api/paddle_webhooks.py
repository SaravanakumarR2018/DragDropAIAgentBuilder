from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from lfx.log.logger import logger

from langflow.services.auth.clerk_metadata_constants import (
    ORGANISATION_CREATED_BY_KEY,
    PADDLE_CUSTOM_DATA_ORG_ID_KEY,
    PADDLE_CUSTOM_DATA_USER_ID_KEY,
    PADDLE_SUBSCRIPTION_ID_KEY,
)
from langflow.services.auth.clerk_utils import update_clerk_organization

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])

_HANDLED_PADDLE_EVENTS = {
    "subscription.created",
    "subscription.activated",
}


def _get_nested_value(payload: dict[str, Any], *keys: str) -> Any:
    current: Any = payload
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


@router.post("/paddle")
async def handle_paddle_webhook(request: Request) -> dict[str, bool]:
    try:
        payload = await request.json()
    except ValueError:
        logger.info("Ignoring Paddle webhook with invalid JSON payload")
        return {"ok": True}

    if not isinstance(payload, dict):
        logger.info("Ignoring Paddle webhook with non-object payload")
        return {"ok": True}

    event_type = _get_nested_value(payload, "event_type")
    subscription_id = _get_nested_value(payload, "data", "id")
    org_id = _get_nested_value(payload, "data", "custom_data", PADDLE_CUSTOM_DATA_ORG_ID_KEY)
    organisation_created_by = _get_nested_value(payload, "data", "custom_data", PADDLE_CUSTOM_DATA_USER_ID_KEY)

    logger.info(
        "Received Paddle webhook: event_type=%s, org_id=%s, subscription_id=%s",
        event_type,
        org_id,
        subscription_id,
    )

    if event_type not in _HANDLED_PADDLE_EVENTS:
        logger.info("Ignoring unsupported Paddle event type: %s", event_type)
        return {"ok": True}

    if not org_id or not subscription_id:
        logger.info(
            "Ignoring Paddle webhook because required metadata is missing: org_id=%s, subscription_id=%s",
            org_id,
            subscription_id,
        )
        return {"ok": True}

    public_metadata = {
        PADDLE_SUBSCRIPTION_ID_KEY: subscription_id,
        ORGANISATION_CREATED_BY_KEY: organisation_created_by,
    }
    logger.info(
        "Updating Clerk organization metadata from Paddle webhook: org_id=%s, subscription_id=%s",
        org_id,
        subscription_id,
    )
    await update_clerk_organization(
        org_id=org_id,
        public_metadata=public_metadata,
    )
    logger.info("Finished processing Paddle webhook for org_id=%s", org_id)
    return {"ok": True}