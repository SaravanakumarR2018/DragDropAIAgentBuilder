"""Paddle Billing plan provisioning."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from paddle_billing.Entities.Shared.CatalogType import CatalogType
from paddle_billing.Entities.Shared.CurrencyCode import CurrencyCode
from paddle_billing.Entities.Shared.Money import Money
from paddle_billing.Entities.Shared.TaxCategory import TaxCategory
from paddle_billing.Entities.Shared.TaxMode import TaxMode
from paddle_billing.Resources.Prices.Operations import CreatePrice
from paddle_billing.Resources.Products.Operations import CreateProduct

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
    """Create Paddle Billing plans."""
    client = get_paddle_client()

    for plan in PLANS:
        product_id = _create_product(plan, client)
        _create_price(plan, product_id, client)
        logger.info("Paddle plan %s provisioned.", plan.key)


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


def _create_price(plan: PlanDefinition, product_id: str, client: Any) -> None:
    amount_cents = int((plan.monthly_price_usd * 100).quantize(Decimal("1")))
    logger.info("Creating Paddle price for plan %s.", plan.key)
    client.prices.create(
        CreatePrice(
            product_id=product_id,
            description=f"{plan.name} Monthly",
            type=CatalogType.Standard,
            tax_mode=TaxMode.External,
            unit_price=Money(amount=str(amount_cents), currency_code=CurrencyCode.USD),
            custom_data={"plan_key": plan.key},
        )
    )
