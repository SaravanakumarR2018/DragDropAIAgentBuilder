from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from lfx.log.logger import logger
from langflow.api.utils import CurrentActiveUser
from langflow.services.auth.clerk_utils import get_paddle_customer_id_from_clerk_payload
from langflow.services.deps import get_settings_service
from langflow.services.paddle.subscriptions import ensure_paddle_customer_for_user

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

    await ensure_paddle_customer_for_user(
        user=current_user,
    )

    return {"created": True}