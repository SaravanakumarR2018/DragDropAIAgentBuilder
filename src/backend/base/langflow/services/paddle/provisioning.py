"""Paddle Billing plan provisioning (idempotent, SDK-only)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from paddle_billing.Entities.Shared.CurrencyCode import CurrencyCode
from paddle_billing.Entities.Shared.Money import Money
from paddle_billing.Entities.Shared.TaxCategory import TaxCategory
from paddle_billing.Entities.Shared.TaxMode import TaxMode
from paddle_billing.Entities.Shared.Duration import Duration
from paddle_billing.Entities.Shared.Interval import Interval
from paddle_billing.Resources.Prices.Operations import CreatePrice
from paddle_billing.Resources.Products.Operations import CreateProduct

from lfx.log.logger import logger
from langflow.services.paddle.client import get_paddle_client


# -------------------------------------------------------------------
# Plan definitions
# -------------------------------------------------------------------

@dataclass(frozen=True)
class PlanDefinition:
    key: str
    name: str
    monthly_price_usd: str  # MUST be string for Paddle Money.amount
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


# -------------------------------------------------------------------
# Public entrypoint
# -------------------------------------------------------------------

def provision_paddle_plans() -> None:
    """
    Idempotently provision Paddle products (plans) and monthly subscription prices.

    Rules:
    - One Product per plan (Starter, Pro)
    - One monthly subscription Price per Product
    - Starter has a trial; Pro does not
    - SDK-only (no raw HTTP)
    """
    client = get_paddle_client()

    products = list(client.products.list())
    prices = list(client.prices.list())

    for plan in PLANS:
        if _find_existing_price(plan, prices):
            logger.info("Paddle plan %s already provisioned; skipping.", plan.key)
            continue

        product = _find_existing_product(plan, products)
        if product:
            product_id = product.id
        else:
            product_id = _create_product(plan, client)

        _create_monthly_price(plan, product_id, client)
        logger.info("Paddle plan %s provisioned.", plan.key)


# -------------------------------------------------------------------
# Find helpers
# -------------------------------------------------------------------

def _find_existing_product(plan: PlanDefinition, products: list[Any]) -> Any | None:
    for product in products:
        if _custom_data_value(product.custom_data, "plan_key") == plan.key:
            return product
    return None


def _find_existing_price(plan: PlanDefinition, prices: list[Any]) -> Any | None:
    for price in prices:
        if _custom_data_value(price.custom_data, "plan_key") == plan.key:
            return price
    return None


def _custom_data_value(custom_data: Any, key: str) -> Any | None:
    """
    Paddle CustomData is NOT a dict.
    Safe accessor that works across SDK versions.
    """
    if not custom_data:
        return None
    try:
        return custom_data[key]
    except Exception:
        return None


# -------------------------------------------------------------------
# Create helpers
# -------------------------------------------------------------------

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
            billing_cycle=billing_cycle,        # subscription
            trial_period=trial_period,          # Starter only
            tax_mode=TaxMode.External,
            unit_price=Money(
                amount=plan.monthly_price_usd,  # MUST be string
                currency_code=CurrencyCode.USD,
            ),
            custom_data={
                "plan_key": plan.key,
                "billing": "monthly",
                "has_trial": bool(plan.trial_days),
            },
        )
    )
