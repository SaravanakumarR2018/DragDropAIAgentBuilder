"""Paddle Billing plan provisioning."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Iterable

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
    """Ensure Paddle Billing plans exist without duplicates."""
    client = get_paddle_client()
    logger.info("Loading existing Paddle products and prices for provisioning.")
    existing_products = _load_products(client)
    existing_prices = _load_prices(client)

    for plan in PLANS:
        product_id = _ensure_product(plan, existing_products, client)
        existing_products = _refresh_products_if_missing(product_id, existing_products, client)
        if _find_existing_price(plan, existing_prices):
            logger.info("Paddle plan %s already exists; skipping price creation.", plan.key)
            continue
        _create_price(plan, product_id, client)
        existing_prices = _load_prices(client)
        logger.info("Paddle plan %s provisioned.", plan.key)


def _load_prices(client: Any) -> list[dict[str, Any]]:
    return _fetch_all(client.prices.list)


def _load_products(client: Any) -> list[dict[str, Any]]:
    return _fetch_all(client.products.list)


def _fetch_all(list_call: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    params: dict[str, Any] = {"per_page": 200}

    while True:
        response = list_call(**params)
        items.extend(_extract_items(response))
        next_cursor = _extract_next_cursor(response)
        if not next_cursor:
            break
        params = {"after": next_cursor, "per_page": 200}

    return items


def _find_existing_price(plan: PlanDefinition, prices: list[dict[str, Any]]) -> dict[str, Any] | None:
    for price in prices:
        custom_data = _get_field(price, "custom_data", {}) or {}
        if _get_field(custom_data, "plan_key") == plan.key:
            return _normalize_payload(price)
        if _get_field(price, "description") == f"{plan.name} Monthly":
            return price
    return None


def _ensure_product(plan: PlanDefinition, products: list[dict[str, Any]], client: Any) -> str:
    for product in products:
        custom_data = _get_field(product, "custom_data", {}) or {}
        if _get_field(custom_data, "plan_key") == plan.key:
            return _get_field(product, "id")
        if _get_field(product, "name") == plan.name:
            return _get_field(product, "id")

    logger.info("Creating Paddle product for plan %s.", plan.key)
    product = client.products.create(
        CreateProduct(
            name=plan.name,
            tax_category=TaxCategory.Standard,
            custom_data={"plan_key": plan.key},
        )
    )
    return _get_field(product, "id")


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


def _get_field(item: Any, key: str, default: Any = None) -> Any:
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def _extract_items(response: Any) -> Iterable[Any]:
    if response is None:
        return []
    if isinstance(response, list):
        return response
    if isinstance(response, dict):
        return response.get("data", [])
    if hasattr(response, "data"):
        return getattr(response, "data") or []
    if hasattr(response, "items"):
        return getattr(response, "items") or []
    if hasattr(response, "__iter__"):
        return list(response)
    return []


def _extract_next_cursor(response: Any) -> str | None:
    if response is None:
        return None
    if isinstance(response, dict):
        return response.get("meta", {}).get("pagination", {}).get("next")
    if hasattr(response, "pagination"):
        pagination = getattr(response, "pagination")
        return _get_field(pagination, "next")
    if hasattr(response, "next"):
        return getattr(response, "next")
    return None


def _normalize_payload(item: Any) -> dict[str, Any]:
    if isinstance(item, dict):
        return item
    if hasattr(item, "to_dict"):
        return item.to_dict()
    return {"id": _get_field(item, "id")}


def _refresh_products_if_missing(product_id: str, products: list[dict[str, Any]], client: Any) -> list[dict[str, Any]]:
    if product_id:
        return products
    logger.warning("Paddle product id missing after creation; reloading products.")
    return _load_products(client)
