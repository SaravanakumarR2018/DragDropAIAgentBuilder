"""Paddle Billing plan provisioning (idempotent, SDK-only)."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any
import importlib.resources

from lfx.log.logger import logger
from paddle_billing import Client  #noqa: TCH002
from paddle_billing.Entities.Shared.CurrencyCode import CurrencyCode
from paddle_billing.Entities.Shared.Duration import Duration
from paddle_billing.Entities.Shared.Interval import Interval
from paddle_billing.Entities.Shared.Money import Money
from paddle_billing.Entities.Shared.TaxCategory import TaxCategory
from paddle_billing.Entities.Shared.TaxMode import TaxMode
from paddle_billing.Resources.Prices.Operations import CreatePrice
from paddle_billing.Resources.Products.Operations import CreateProduct

from langflow.services.paddle.client import get_paddle_client
from langflow.services.paddle.subscriptions import _normalize_custom_data
from langflow.services.auth.clerk_metadata_constants import PADDLE_LOCK_KEY


@dataclass(frozen=True)
class PlanDefinition:
    key: str
    name: str
    monthly_price_usd: str
    trial_days: int | None = None


@lru_cache(maxsize=1)
def _load_plan_config() -> dict:
    config_path = Path(__file__).parents[2] / "frontend" / "plan_config.json"

    logger.info(f"Loading Paddle plan config from: {config_path}")

    with config_path.open("r", encoding="utf-8") as f:
        return json.load(f)

def _get_paddle_plans() -> tuple[PlanDefinition, ...]:
    plans = []
    for plan in _load_plan_config().get("plans", []):
        paddle = plan.get("paddle", {})
        if not paddle.get("enabled"):
            continue
        plans.append(
            PlanDefinition(
                key=str(paddle["plan_key"]),
                name=str(plan["name"]).replace(" Pack", ""),
                monthly_price_usd=str(paddle["monthly_price_usd_cents"]),
                trial_days=paddle.get("trial_days"),
            )
        )
    return tuple(plans)


def provision_paddle_plans() -> None:
    """Idempotently provision Paddle products (plans) and monthly subscription prices."""

    client = get_paddle_client()

    # Fetch ALL products & prices once
    products = list(client.products.list())
    prices = list(client.prices.list())

    # Check provisioning lock (do NOT early return)
    has_lock = any(
        _custom_data_value(product.custom_data, "lock") == PADDLE_LOCK_KEY
        for product in products
    )

    if has_lock:
        logger.info("Provisioning lock found — continuing idempotent checks.")

    # Provision plans (idempotent)
    for plan in _get_paddle_plans():
        product = _find_existing_product(plan, products)
        existing_price = _find_existing_price(plan, prices, product)

        if existing_price:
            logger.info("Paddle plan %s already provisioned; skipping.", plan.key)
            continue

        product_id = product.id if product else _create_product(plan, client)

        _create_monthly_price(plan, product_id, client)
        logger.info("Paddle plan %s provisioned.", plan.key)

    # Create provisioning lock (safe, idempotent)
    _create_provisioning_lock(client)


def _find_existing_product(plan: PlanDefinition, products: list[Any]) -> Any | None:
    for product in products:
        if _custom_data_value(product.custom_data, "plan_key") == plan.key:
            return product
        if getattr(product, "name", None) == plan.name:
            return product
    return None


def _find_existing_price(
    plan: PlanDefinition, prices: list[Any], product: Any | None
) -> Any | None:
    for price in prices:
        if _custom_data_value(price.custom_data, "plan_key") == plan.key:
            return price
        if product and _price_matches_plan(plan, price, product.id):
            return price
    return None


def _price_matches_plan(plan: PlanDefinition, price: Any, product_id: str) -> bool:
    if getattr(price, "product_id", None) != product_id:
        return False
    if getattr(price, "description", None) != f"{plan.name} Monthly":
        return False
    if not _duration_matches(price.billing_cycle, Interval.Month, 1):
        return False
    if plan.trial_days:
        if not _duration_matches(price.trial_period, Interval.Day, plan.trial_days):
            return False
    elif price.trial_period is not None:
        return False
    unit_price = getattr(price, "unit_price", None)
    amount = getattr(unit_price, "amount", None)
    currency = getattr(unit_price, "currency_code", None)
    return str(amount) == plan.monthly_price_usd and currency == CurrencyCode.USD


def _duration_matches(duration: Any, interval: Interval, frequency: int) -> bool:
    if duration is None:
        return False
    return (
        getattr(duration, "interval", None) == interval
        and getattr(duration, "frequency", None) == frequency
    )


def _custom_data_value(custom_data: Any, key: str) -> Any | None:
    normalized_custom_data = _normalize_custom_data(custom_data)
    if not normalized_custom_data:
        return None
    return normalized_custom_data.get(key)


def _has_provisioning_lock(client: Any) -> bool:
    return any(
        _custom_data_value(product.custom_data, "lock") == PADDLE_LOCK_KEY
        for product in client.products.list()
    )


def _create_provisioning_lock(client: Any) -> None:
    if _has_provisioning_lock(client):
        logger.info("Paddle provisioning lock already exists; skipping lock creation.")
        return

    client.products.create(
        CreateProduct(
            name="Paddle Provisioning Lock",
            tax_category=TaxCategory.Standard,
            custom_data={"lock": PADDLE_LOCK_KEY},
        )
    )


def _create_product(plan: PlanDefinition, client: Any) -> str:
    logger.info("Creating Paddle product for plan %s.", plan.key)

    product = client.products.create(
        CreateProduct(
            name=plan.name,
            tax_category=TaxCategory.Standard,
            custom_data={"plan_key": plan.key},
        )
    )
    return product.id


def _create_monthly_price(plan: PlanDefinition, product_id: str, client: Any) -> None:
    logger.info("Creating monthly subscription price for plan %s.", plan.key)

    billing_cycle = Duration(interval=Interval.Month, frequency=1)

    trial_period = (
        Duration(interval=Interval.Day, frequency=plan.trial_days)
        if plan.trial_days
        else None
    )

    client.prices.create(
        CreatePrice(
            product_id=product_id,
            description=f"{plan.name} Monthly",
            billing_cycle=billing_cycle,
            trial_period=trial_period,
            tax_mode=TaxMode.External,
            unit_price=Money(
                amount=plan.monthly_price_usd,
                currency_code=CurrencyCode.USD,
            ),
            custom_data={
                "plan_key": plan.key,
                "billing": "monthly",
                "has_trial": bool(plan.trial_days),
            },
        )
    )


async def get_paddle_prices(
    *,
    client: Client | None = None,
) -> dict[str, str]:

    paddle_client = client or get_paddle_client()

    try:
        prices = await asyncio.to_thread(
            lambda: list(paddle_client.prices.list())
        )
    except Exception as exc:
        logger.exception(f"Failed to fetch Paddle prices: {exc}")
        msg="Failed to fetch Paddle prices"
        raise ValueError(msg) from exc

    price_map: dict[str, str] = {}

    for price in prices:
        custom_data = _normalize_custom_data(
            getattr(price, "custom_data", None)
        )

        plan_key = custom_data.get("plan_key")

        if isinstance(plan_key, str) and price.id:
            price_map[plan_key] = price.id

    if not price_map:
        msg="No Paddle price IDs found — make sure plans are provisioned"
        raise ValueError(msg)

    return price_map
