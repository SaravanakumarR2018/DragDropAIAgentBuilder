"""Paddle Billing plan provisioning."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from lfx.log.logger import logger

from langflow.services.paddle.client import get_paddle_client


@dataclass(frozen=True)
class PlanDefinition:
    key: str
    name: str
    monthly_price_usd: Decimal
    trial_days: int | None = None


PLANS: tuple[PlanDefinition, ...] = (
    PlanDefinition(key="starter_pack_monthly", name="Starter", monthly_price_usd=Decimal("20.00"), trial_days=7),
    PlanDefinition(key="pro_pack_monthly", name="Pro", monthly_price_usd=Decimal("50.00")),
    PlanDefinition(key="enterprise_pack_monthly", name="Enterprise", monthly_price_usd=Decimal("0.00")),
)


def provision_paddle_plans() -> None:
    """Ensure Paddle Billing plans exist without duplicates."""
    client = get_paddle_client()
    existing_prices = _load_prices(client)
    existing_products = _load_products(client)

    for plan in PLANS:
        if _find_existing_price(plan, existing_prices):
            logger.info("Paddle plan %s already exists; skipping.", plan.key)
            continue

        product_id = _ensure_product(plan, existing_products, client)
        _create_price(plan, product_id, client)
        logger.info("Paddle plan %s provisioned.", plan.key)


def _load_prices(client: Any) -> list[dict[str, Any]]:
    return _fetch_all(client, "/prices")


def _load_products(client: Any) -> list[dict[str, Any]]:
    return _fetch_all(client, "/products")


def _fetch_all(client: Any, endpoint: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    params: dict[str, Any] | None = {"per_page": 200}

    while True:
        response = client.get_raw(endpoint, params)
        payload = response.json()
        data = payload.get("data") if isinstance(payload, dict) else payload
        if isinstance(data, list):
            items.extend(data)

        pagination = payload.get("meta", {}).get("pagination", {}) if isinstance(payload, dict) else {}
        next_cursor = pagination.get("next")
        if not next_cursor:
            break
        params = {"after": next_cursor, "per_page": 200}

    return items


def _find_existing_price(plan: PlanDefinition, prices: list[dict[str, Any]]) -> dict[str, Any] | None:
    for price in prices:
        custom_data = price.get("custom_data", {})
        if custom_data.get("plan_key") == plan.key:
            return price
        if price.get("name") == f"{plan.name} Monthly":
            return price
    return None


def _ensure_product(plan: PlanDefinition, products: list[dict[str, Any]], client: Any) -> str:
    for product in products:
        custom_data = product.get("custom_data", {})
        if custom_data.get("plan_key") == plan.key:
            return product["id"]
        if product.get("name") == plan.name:
            return product["id"]

    payload = {
        "name": plan.name,
        "type": "standard",
        "tax_category": "standard",
        "custom_data": {"plan_key": plan.key},
    }
    response = client.post_raw("/products", payload)
    product = response.json().get("data", {})
    return product["id"]


def _create_price(plan: PlanDefinition, product_id: str, client: Any) -> None:
    amount_cents = int((plan.monthly_price_usd * 100).quantize(Decimal("1")))
    payload: dict[str, Any] = {
        "product_id": product_id,
        "name": f"{plan.name} Monthly",
        "unit_price": {"amount": str(amount_cents), "currency_code": "USD"},
        "billing_cycle": {"interval": "month", "frequency": 1},
        "custom_data": {"plan_key": plan.key},
    }
    if plan.trial_days:
        payload["trial_period"] = {"interval": "day", "frequency": plan.trial_days}

    client.post_raw("/prices", payload)