from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from lfx.log.logger import logger
from langflow.api.utils import CurrentActiveUser
from langflow.services.auth.clerk_utils import (
    get_clerk_organization,
    get_clerk_user_id_from_payload,
    get_org_id_from_clerk_payload,
    get_paddle_customer_id_from_clerk_payload,
    update_clerk_organization,
)
from langflow.services.deps import get_settings_service
from langflow.services.paddle.subscriptions import (
    create_subscription_for_customer,
    ensure_paddle_customer_for_user,
    has_active_subscription,
)

router = APIRouter(tags=["Billing"], prefix="/billing")


class EnsurePaddleCustomerRequest(BaseModel):
    email: str | None = None


class CreateSubscriptionRequest(BaseModel):
    plan_key: str
    quantity: int


@router.post("/ensure-paddle-customer")
async def ensure_paddle_customer(
    current_user: CurrentActiveUser,
) -> dict:
    """Ensure the current user has a Paddle customer id in Clerk metadata."""
    if not get_settings_service().auth_settings.CLERK_AUTH_ENABLED:
        raise HTTPException(status_code=400, detail="Clerk auth not enabled")

    logger.info(f"Ensuring Paddle customer for user {current_user.id}")
    existing_customer_id = await get_paddle_customer_id_from_clerk_payload()
    logger.info(f"Existing Paddle customer id: {existing_customer_id}")
    if existing_customer_id:
        return {"created": False}

    await ensure_paddle_customer_for_user(
        user=current_user,
    )

    return {"created": True}


@router.get("/subscription-status")
async def subscription_status(
    current_user: CurrentActiveUser,
) -> dict:
    """Check Paddle subscription status for the current organization."""
    if not get_settings_service().auth_settings.CLERK_AUTH_ENABLED:
        raise HTTPException(status_code=400, detail="Clerk auth not enabled")

    logger.info(f"Checking subscription status for user {current_user.id}")
    return await has_active_subscription()


@router.post("/create-subscription")
async def create_subscription(
    payload: CreateSubscriptionRequest,
    current_user: CurrentActiveUser,
) -> dict:
    """Create a Paddle subscription and update Clerk organization metadata."""
    if not get_settings_service().auth_settings.CLERK_AUTH_ENABLED:
        raise HTTPException(status_code=400, detail="Clerk auth not enabled")

    if payload.quantity < 1:
        raise HTTPException(status_code=400, detail="Quantity must be at least 1")

    org_id = get_org_id_from_clerk_payload()
    clerk_user_id = get_clerk_user_id_from_payload()

    existing_customer_id = await get_paddle_customer_id_from_clerk_payload()
    paddle_customer_id = existing_customer_id or await ensure_paddle_customer_for_user(
        user=current_user,
    )

    subscription = await create_subscription_for_customer(
        customer_id=paddle_customer_id,
        plan_key=payload.plan_key,
        quantity=payload.quantity,
        org_id=org_id,
    )

    organization = await get_clerk_organization(org_id)
    public_metadata = organization.get("public_metadata", {}) if isinstance(organization, dict) else {}
    merged_metadata = {
        **public_metadata,
        "paddle_subscription_id": subscription.id,
        "organisation_created_by": public_metadata.get("organisation_created_by") or clerk_user_id,
    }

    # Update organization metadata (not user metadata) with subscription info.
    await update_clerk_organization(
        org_id=org_id,
        public_metadata=merged_metadata,
        max_allowed_members=payload.quantity,
    )

    return {
        "subscription_id": subscription.id,
        "status": getattr(subscription, "status", None),
    }
