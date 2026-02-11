from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from lfx.log.logger import logger
from langflow.api.utils import CurrentActiveUser
from langflow.services.auth.clerk_utils import (
    get_clerk_user_id_from_payload,
    get_organisation_created_by_from_clerk_payload,
    get_paddle_customer_id_from_clerk_payload,
    get_paddle_subscription_id_from_clerk_payload,
)
from langflow.services.deps import get_settings_service
from langflow.services.paddle.subscriptions import (
    ensure_paddle_customer_for_user,
    has_active_subscription,
)

router = APIRouter(tags=["Billing"], prefix="/billing")


class EnsurePaddleCustomerRequest(BaseModel):
    email: str | None = None


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

    await ensure_paddle_customer_for_user()

    return {"created": True}


@router.get("/org-access")
async def get_org_access(
    current_user: CurrentActiveUser,
) -> dict:
    """Evaluate org access based on Clerk metadata + Paddle subscription state."""
    if not get_settings_service().auth_settings.CLERK_AUTH_ENABLED:
        raise HTTPException(status_code=400, detail="Clerk auth not enabled")

    current_user_id = get_clerk_user_id_from_payload()
    logger.info(f"Checking org access for user {current_user.id}")
    organisation_created_by = await get_organisation_created_by_from_clerk_payload()
    logger.info(f"Organisation created by: {organisation_created_by}")
    paddle_subscription_id = await get_paddle_subscription_id_from_clerk_payload()
    logger.info(f"Paddle subscription id: {paddle_subscription_id}")
    is_admin = bool(
        organisation_created_by
        and current_user_id.strip() == organisation_created_by.strip()
    )
    logger.info(f"Is admin: {is_admin}")

    if not organisation_created_by:
        logger.info("Organisation created by missing, denying access")
        return {
            "has_access": False,
            "is_admin": True,
            "redirect_to": "/pricing",
            "reason": "organisation_created_by_missing",
            "organisation_created_by": None,
            "paddle_subscription_id": paddle_subscription_id,
            "subscription_status": None,
        }

    if not paddle_subscription_id:
        logger.info("Paddle subscription id missing, denying access")
        return {
            "has_access": False,
            "is_admin": is_admin,
            "redirect_to": "/pricing" if is_admin else None,
            "reason": "paddle_subscription_id_missing",
            "organisation_created_by": organisation_created_by,
            "paddle_subscription_id": None,
            "subscription_status": None,
        }

    logger.info(f"Checking subscription status for subscription {paddle_subscription_id}")
    subscription_access = await has_active_subscription(
        subscription_id=paddle_subscription_id,
    )
    logger.info(f"Subscription access result: {subscription_access}")

    if subscription_access["has_access"]:
        logger.info("Subscription active, granting access")
        return {
            **subscription_access,
            "is_admin": is_admin,
            "redirect_to": "/flows",
            "reason": "subscription_active",
        }

    logger.info("Subscription inactive, denying access")
    return {
        **subscription_access,
        "is_admin": is_admin,
        "redirect_to": "/pricing" if is_admin else None,
        "reason": "subscription_inactive",
    }