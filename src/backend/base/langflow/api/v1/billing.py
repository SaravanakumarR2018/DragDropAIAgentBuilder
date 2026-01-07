from __future__ import annotations

import os
from typing import Literal

import httpx
from fastapi import APIRouter, HTTPException, status
from pydantic import AnyHttpUrl, BaseModel

from langflow.api.utils import CurrentActiveUser

router = APIRouter(prefix="/billing", tags=["Billing"])


class CheckoutSessionRequest(BaseModel):
    plan: Literal["standard", "pro"]
    success_url: AnyHttpUrl
    cancel_url: AnyHttpUrl


class CheckoutSessionResponse(BaseModel):
    url: AnyHttpUrl


PLAN_CONFIG = {
    "standard": {
        "name": "Standard",
        "amount": 2000,
        "description": "Standard monthly subscription",
    },
    "pro": {
        "name": "Pro",
        "amount": 5000,
        "description": "Pro monthly subscription",
    },
}


def _get_stripe_secret_key() -> str:
    direct_key = os.getenv("STRIPE_SECRET_KEY")
    if direct_key:
        return direct_key
    environment = (
        os.getenv("LANGFLOW_ENVIRONMENT")
        or os.getenv("ENVIRONMENT")
        or os.getenv("APP_ENV")
        or "prod"
    ).lower()
    key_name = "STAGING_STRIPE_TOKEN" if environment.startswith("stag") else "PROD_STRIPE_TOKEN"
    token = os.getenv(key_name)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Stripe token not configured for {environment} environment.",
        )
    return token


@router.post("/stripe/checkout", response_model=CheckoutSessionResponse)
async def create_stripe_checkout_session(
    payload: CheckoutSessionRequest,
    current_user: CurrentActiveUser,
) -> CheckoutSessionResponse:
    plan = PLAN_CONFIG.get(payload.plan)
    if not plan:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid plan selection.")

    secret_key = _get_stripe_secret_key()
    request_data = {
        "mode": "subscription",
        "success_url": str(payload.success_url),
        "cancel_url": str(payload.cancel_url),
        "client_reference_id": str(current_user.id),
        "line_items[0][price_data][currency]": "usd",
        "line_items[0][price_data][unit_amount]": str(plan["amount"]),
        "line_items[0][price_data][product_data][name]": f"{plan['name']} Plan",
        "line_items[0][price_data][product_data][description]": plan["description"],
        "line_items[0][price_data][recurring][interval]": "month",
        "line_items[0][quantity]": "1",
        "allow_promotion_codes": "true",
    }

    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.post(
            "https://api.stripe.com/v1/checkout/sessions",
            data=request_data,
            headers={"Authorization": f"Bearer {secret_key}"},
        )

    if response.status_code >= 400:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to create Stripe checkout session.",
        )

    response_data = response.json()
    checkout_url = response_data.get("url")
    if not checkout_url:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Stripe checkout session missing URL.",
        )

    return CheckoutSessionResponse(url=checkout_url)
