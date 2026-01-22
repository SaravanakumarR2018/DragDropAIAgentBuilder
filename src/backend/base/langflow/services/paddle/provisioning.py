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

    logger.info("Loading existing Paddle products and prices for provisioning.")
    logger.info("Loaded %d existing products.", len(existing_products))
    existing_prices = _load_prices(client)
        product_id = _ensure_product(plan, existing_products, client)
        existing_products = _refresh_products_if_missing(product_id, existing_products, client)
            logger.info("Paddle plan %s already exists; skipping price creation.", plan.key)
        existing_prices = _load_prices(client)
    return _fetch_all(client.prices.list)
    return _fetch_all(client.products.list)
def _fetch_all(list_call: Any) -> list[dict[str, Any]]:
    params: dict[str, Any] = {"per_page": 200}
        response = list_call(**params)
        items.extend(_extract_items(response))
        next_cursor = _extract_next_cursor(response)
        custom_data = _get_field(price, "custom_data", {}) or {}
        if _get_field(custom_data, "plan_key") == plan.key:
            return _normalize_payload(price)
        if _get_field(price, "description") == f"{plan.name} Monthly":

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
