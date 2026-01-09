from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm.attributes import flag_modified
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.services.database.models.user.crud import get_user_by_id
from langflow.services.database.models.user.model import User


ACCESS_ACTIVE_STATUSES = {"active", "trialing"}


def _parse_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def compute_has_access(optins: dict[str, Any]) -> bool:
    if optins.get("skip_trial_access"):
        return True

    subscription_status = optins.get("stripe_subscription_status")
    if subscription_status in ACCESS_ACTIVE_STATUSES:
        return True

    trial_until = _parse_iso_datetime(optins.get("trial_access_until"))
    if trial_until and trial_until > datetime.now(timezone.utc):
        return True

    return False


def set_has_access_optin(optins: dict[str, Any]) -> dict[str, Any]:
    updated = {**optins}
    updated["has_access"] = compute_has_access(updated)
    return updated


async def update_user_optins(
    session: AsyncSession,
    user: User,
    updates: dict[str, Any],
) -> User:
    optins = {**(user.optins or {})}
    optins.update(updates)
    optins = set_has_access_optin(optins)
    user.optins = optins
    flag_modified(user, "optins")
    await session.commit()
    await session.refresh(user)
    return user


async def ensure_user_has_access(session: AsyncSession, user: User) -> User:
    optins = {**(user.optins or {})}
    updated = set_has_access_optin(optins)
    if updated != optins:
        user.optins = updated
        flag_modified(user, "optins")
        await session.commit()
        await session.refresh(user)
    return user


async def update_user_from_stripe_payload(
    session: AsyncSession,
    user_id: str | None,
    updates: dict[str, Any],
) -> User | None:
    if not user_id:
        return None

    user = await get_user_by_id(session, user_id)
    if not user:
        return None

    return await update_user_optins(session, user, updates)
