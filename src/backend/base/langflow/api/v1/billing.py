from fastapi import APIRouter, HTTPException
from langflow.services.auth.clerk_metadata_constants import (
    CANCEL_SCHEDULED_KEY,
    CURRENT_PERIOD_END_KEY,
    CURRENT_PERIOD_START_KEY,
    HAS_ACCESS_KEY,
    NEXT_BILLED_AT_KEY,
    ORGANISATION_CREATED_BY,
    PADDLE_SUBSCRIPTION_ID,
    PADDLE_SUBSCRIPTION_ID_KEY,
    SUBSCRIPTION_SEATS_KEY,
    SUBSCRIPTION_STATUS_KEY,
)
from lfx.log.logger import logger
from pydantic import BaseModel

from langflow.api.utils import CurrentActiveUser
from langflow.services.auth.clerk_utils import (
    get_clerk_user_id_from_payload,
    get_org_id_from_clerk_payload,
    get_organisation_created_by_from_clerk_payload,
    get_paddle_customer_id_from_clerk_payload,
    get_paddle_subscription_id_from_clerk_payload,
    update_clerk_organization,
)
from langflow.services.deps import get_settings_service
from langflow.services.paddle.provisioning import get_paddle_prices
from langflow.services.paddle.subscriptions import (
    _ensure_admin_user,
    cancel_subscription,
    change_subscription,
    ensure_paddle_customer_for_user,
    fetch_active_subscription,
    has_active_subscription,
    preview_subscription_update,
    retry_with_backoff,
    update_subscription_plan,
    update_subscription_seats,
)

router = APIRouter(tags=["Billing"], prefix="/billing")


class EnsurePaddleCustomerRequest(BaseModel):
    email: str | None = None

class ChangeSubscriptionRequest(BaseModel):
    price_id: str
    quantity: int = 1
    is_upgrade: bool

class ChangePlanRequest(BaseModel):
    price_id: str
    seats: int

class ChangeSeatsRequest(BaseModel):
    seats: int

class PreviewChangeRequest(BaseModel):
    price_id: str | None = None
    seats: int

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
            HAS_ACCESS_KEY: False,
            "is_admin": True,
            "reason": "organisation_created_by_missing",
            ORGANISATION_CREATED_BY: None,
            PADDLE_SUBSCRIPTION_ID: paddle_subscription_id,
            SUBSCRIPTION_STATUS_KEY: None,
            CURRENT_PERIOD_START_KEY: None,
            CURRENT_PERIOD_END_KEY: None,
            NEXT_BILLED_AT_KEY: None,
            CANCEL_SCHEDULED_KEY: False,
            SUBSCRIPTION_SEATS_KEY: None,
        }

    if not paddle_subscription_id:
        logger.info("Paddle subscription id missing, denying access")
        return {
            HAS_ACCESS_KEY: False,
            "is_admin": is_admin,
            "reason": "paddle_subscription_id_missing",
            ORGANISATION_CREATED_BY: organisation_created_by,
            PADDLE_SUBSCRIPTION_ID: None,
            SUBSCRIPTION_STATUS_KEY: None,
            CURRENT_PERIOD_START_KEY: None,
            CURRENT_PERIOD_END_KEY: None,
            NEXT_BILLED_AT_KEY: None,
            CANCEL_SCHEDULED_KEY: False,
            SUBSCRIPTION_SEATS_KEY: None,
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
            "reason": "subscription_active",
        }

    logger.info("Subscription inactive, denying access")
    return {
        **subscription_access,
        "is_admin": is_admin,
        "reason": "subscription_inactive",
    }

@router.get("/paddle-prices")
async def list_paddle_prices():
    """Return a mapping of plan_key -> Paddle price_id."""
    try:
        return await get_paddle_prices()
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) # noqa: B904
    except Exception as exc: #noqa: BLE001
        logger.exception(f"Error fetching Paddle prices {exc}")
        raise HTTPException(status_code=500, detail="Internal server error") #noqa: B904


@router.post("/get-subscriptions")
async def get_subscriptions_by_customer(
    current_user: CurrentActiveUser,
) -> dict:

    if not get_settings_service().auth_settings.CLERK_AUTH_ENABLED:
        raise HTTPException(status_code=400, detail="Clerk auth not enabled")

    customer_id = await get_paddle_customer_id_from_clerk_payload()
    org_id = get_org_id_from_clerk_payload()

    if not customer_id:
        raise HTTPException(status_code=400, detail="Missing paddle_customer_id")
    
    subscriptions = []
    active_sub_id = None

    try:
        active_sub_id, subscriptions = await fetch_active_subscription(customer_id, org_id)
    except ValueError:
        pass
    if not active_sub_id:
        try:
            active_sub_id, subscriptions = await retry_with_backoff(
                lambda: fetch_active_subscription(customer_id, org_id),
                retries=3,
                base_delay=2,
                max_delay=5,
                retry_exceptions=(ValueError,),  # retry only for this
            )

        except ValueError:
            return {
                "updated": False,
                "reason": "no_active_subscription",
                "subscriptions": subscriptions,
            }

    # 3️⃣ Update Clerk org metadata
    await update_clerk_organization(
        org_id=org_id,
        public_metadata={PADDLE_SUBSCRIPTION_ID_KEY: active_sub_id},
    )

    return {
        "updated": True,
        "subscription_id": active_sub_id,
        "total_subscriptions": len(subscriptions),
    }

class CancelSubscriptionRequest(BaseModel):
    effective_from_immediately: bool = False


@router.post("/cancel-subscription")
async def cancel_subscription_api(
    body: CancelSubscriptionRequest,
    current_user: CurrentActiveUser,
) -> dict:
    """Cancel subscription using Paddle"""

    if not get_settings_service().auth_settings.CLERK_AUTH_ENABLED:
        raise HTTPException(status_code=400, detail="Clerk auth not enabled")
    
    await _ensure_admin_user()

    # Get subscription_id from Clerk metadata (JWT)
    subscription_id = await get_paddle_subscription_id_from_clerk_payload()

    if not subscription_id:
        raise HTTPException(status_code=400, detail="Missing paddle_subscription_id")

    logger.info(
        f"Cancel request for subscription {subscription_id}, "
        f"immediate={body.effective_from_immediately}"
    )

    try:
        result = await cancel_subscription(
            subscription_id=subscription_id,
            effective_from_immediately=body.effective_from_immediately,
        )

        return {
            "success": True,
            "message": "Subscription cancellation triggered",
            **result,
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to cancel subscription: {str(e)}",
        )

@router.post("/change-subscription")
async def change_subscription_api(
    body: ChangeSubscriptionRequest,
    current_user: CurrentActiveUser,
) -> dict:
    """Change subscription (Starter -> Pro)"""

    logger.info(f"Change subscription API called by user {current_user.id}")

    if not get_settings_service().auth_settings.CLERK_AUTH_ENABLED:
        raise HTTPException(status_code=400, detail="Clerk auth not enabled")
    
    await _ensure_admin_user()

    # 1️⃣ Get subscription_id from Clerk metadata
    subscription_id = await get_paddle_subscription_id_from_clerk_payload()

    if not subscription_id:
        raise HTTPException(status_code=400, detail="Missing paddle_subscription_id")

    logger.info(
        f"Upgrade request for subscription {subscription_id} "
        f"to price {body.price_id}"
    )

    try:
        result = await change_subscription(
            subscription_id=subscription_id,
            new_price_id=body.price_id,
            quantity=body.quantity,
            is_upgrade=body.is_upgrade,
        )

        logger.info(
            f"Successfully changed subscription {subscription_id} "
            f"to price {body.price_id}, status: {result.get('status')}"
        )

        return {
            "success": True,
            "message": "Subscription changed successfully",
            **result,
        }

    except Exception as e:
        logger.info(
            f"Failed to upgrade subscription {subscription_id} "
            f"for user {current_user.id}: {str(e)}"
        )
        raise HTTPException(
            status_code=500,
            detail=f"Failed to upgrade subscription: {str(e)}",
        )


@router.post("/preview-change")
async def preview_change_api(
    body: PreviewChangeRequest,
    current_user: CurrentActiveUser,
):
    if not get_settings_service().auth_settings.CLERK_AUTH_ENABLED:
        raise HTTPException(status_code=400, detail="Clerk auth not enabled")

    await _ensure_admin_user()

    subscription_id = await get_paddle_subscription_id_from_clerk_payload()

    if not subscription_id:
        raise HTTPException(status_code=400, detail="Missing subscription_id")

    return await preview_subscription_update(
        subscription_id=subscription_id,
        new_price_id=body.price_id,
        new_quantity=body.seats,
    )

@router.post("/change-plan")
async def change_plan_api(
    body: ChangePlanRequest,
    current_user: CurrentActiveUser,
):
    if not get_settings_service().auth_settings.CLERK_AUTH_ENABLED:
        raise HTTPException(status_code=400, detail="Clerk auth not enabled")

    await _ensure_admin_user()

    subscription_id = await get_paddle_subscription_id_from_clerk_payload()

    if not subscription_id:
        raise HTTPException(status_code=400, detail="Missing subscription_id")

    result = await update_subscription_plan(
        subscription_id=subscription_id,
        new_price_id=body.price_id,
        quantity=body.seats,
    )

    return {
        "success": True,
        "message": "Plan updated successfully",
        **result,
    }

@router.post("/change-seats")
async def change_seats_api(
    body: ChangeSeatsRequest,
    current_user: CurrentActiveUser,
):
    if not get_settings_service().auth_settings.CLERK_AUTH_ENABLED:
        raise HTTPException(status_code=400, detail="Clerk auth not enabled")

    await _ensure_admin_user()

    subscription_id = await get_paddle_subscription_id_from_clerk_payload()

    if not subscription_id:
        raise HTTPException(status_code=400, detail="Missing subscription_id")

    result = await update_subscription_seats(
        subscription_id=subscription_id,
        new_quantity=body.seats,
    )

    return {
        "success": True,
        "message": "Seats updated successfully",
        **result,
    }