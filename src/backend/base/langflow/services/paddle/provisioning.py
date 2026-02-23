"""Paddle Billing plan provisioning (idempotent, SDK-only)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from langflow.services.paddle.client import get_paddle_client
from lfx.log.logger import logger
from paddle_billing import Client
from paddle_billing.Entities.Shared.CurrencyCode import CurrencyCode
from paddle_billing.Entities.Shared.Duration import Duration
from paddle_billing.Entities.Shared.Interval import Interval
from paddle_billing.Entities.Shared.Money import Money
from paddle_billing.Entities.Shared.TaxCategory import TaxCategory
from paddle_billing.Entities.Shared.TaxMode import TaxMode
from paddle_billing.Resources.Prices.Operations import CreatePrice
from paddle_billing.Resources.Products.Operations import CreateProduct


@dataclass(frozen=True)
class PlanDefinition:
    key: str
    name: str
    monthly_price_usd: str
    trial_days: int | None = None


PLANS: tuple[PlanDefinition, ...] = (
    PlanDefinition(
        key="starter_pack_monthly",
        name="Starter",
        monthly_price_usd="2000",
        trial_days=7,
    ),
    PlanDefinition(
        key="pro_pack_monthly",
        name="Pro",
        monthly_price_usd="5000",
        trial_days=None,
    ),
)


def provision_paddle_plans() -> None:
    """Idempotently provision Paddle products (plans) and monthly subscription prices."""
    from langflow.services.paddle.client import get_paddle_client

    client = get_paddle_client()

    if not _acquire_provisioning_lock(client):
        logger.info("Paddle provisioning already in progress or completed; skipping.")
        return

    products = list(client.products.list())
    prices = list(client.prices.list())

    for plan in PLANS:
        product = _find_existing_product(plan, products)
        if _find_existing_price(plan, prices, product):
            logger.info("Paddle plan %s already provisioned; skipping.", plan.key)
            continue

        product_id = product.id if product else _create_product(plan, client)

        _create_monthly_price(plan, product_id, client)
        logger.info("Paddle plan %s provisioned.", plan.key)


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
    if not custom_data:
        return None
    try:
        return custom_data[key]
    except Exception:  # noqa: BLE001
        return None


def _acquire_provisioning_lock(client: Any) -> bool:
    LOCK_KEY = "paddle_provisioning_lock" #noqa:N806

    for product in client.products.list():
        if _custom_data_value(product.custom_data, "lock") == LOCK_KEY:
            return False

    try:
        client.products.create(
            CreateProduct(
                name="Paddle Provisioning Lock",
                tax_category=TaxCategory.Standard,
                custom_data={"lock": LOCK_KEY},
            )
        )
        return True #noqa:TRY300
    except Exception: #noqa: BLE001
        return False


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
    """Fetch all Paddle prices and map them by plan_key.
    
    Returns a mapping of plan_key -> paddle price_id for provisioned products.
    Raises ValueError if no prices are found.
    """
    paddle_client = client or get_paddle_client()
    
    try:
        prices = await asyncio.to_thread(lambda: list(paddle_client.prices.list()))
    except Exception as exc:
        logger.exception("Failed to fetch Paddle prices")
        raise ValueError("Failed to fetch Paddle prices") from exc
    
    # Build mapping from plan_key to price_id
    price_map: dict[str, str] = {}
    for price in prices:
        custom_data = getattr(price, "custom_data", {}) or {}
        plan_key = custom_data.get("plan_key")
        if isinstance(plan_key, str) and price.id:
            price_map[plan_key] = price.id
    
    if not price_map:
        raise ValueError(
            "No Paddle price IDs found — make sure plans are provisioned"
        )
    
    return price_map