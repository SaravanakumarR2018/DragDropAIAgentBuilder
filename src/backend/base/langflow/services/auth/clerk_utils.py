import uuid
from datetime import datetime, timedelta, timezone
from contextvars import ContextVar, Token
from typing import Any, Literal
from uuid import UUID, NAMESPACE_URL, uuid5

import httpx
from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from jose import JWTError, jwk, jwt
from sqlmodel.ext.asyncio.session import AsyncSession
from starlette.status import HTTP_401_UNAUTHORIZED

from langflow.logging.logger import logger
from langflow.services.database.constants import DUMMY_USER_NAMESPACE_TEMPLATE
from langflow.services.database.models.user import User
from langflow.services.database.models.user.crud import get_user_by_id
from langflow.services.deps import get_settings_service
from langflow.services.auth.clerk_metadata_constants import (
    CLERK_JWT_SUB_KEY,
    CLERK_JWT_EMAIL_KEY,
    CLERK_JWT_ORG_KEY,
    CLERK_JWT_UUID_KEY,
    PADDLE_CUSTOMER_ID_KEY,
    PADDLE_SUBSCRIPTION_ID_KEY,
    ORGANISATION_CREATED_BY_KEY,
    ORG_ID_KEY,
)

# Context variable to store decoded clerk claims per request
auth_header_ctx: ContextVar[dict | None] = ContextVar("auth_header_ctx", default=None)

_jwks_cache: dict[str, dict[str, Any]] = {}

CLERK_API_BASE = "https://api.clerk.com/v1"

ClerkResourceType = Literal["user", "organization"]


class ClerkPublicMetadataManager:
    """Read/merge/update Clerk public metadata without dropping unrelated keys."""

    def __init__(self, *, resource_type: ClerkResourceType, resource_id: str) -> None:
        self.resource_type = resource_type
        self.resource_id = resource_id

    @classmethod
    def for_user(cls, clerk_user_id: str) -> "ClerkPublicMetadataManager":
        return cls(resource_type="user", resource_id=clerk_user_id)

    @classmethod
    def for_organization(cls, organization_id: str) -> "ClerkPublicMetadataManager":
        return cls(resource_type="organization", resource_id=organization_id)

    @staticmethod
    def merge_metadata(existing: dict | None, updates: dict) -> dict:
        base = dict(existing or {})
        base.update(updates)
        return base

    def _get_headers(self) -> dict:
        settings_service = get_settings_service()
        secret_key = settings_service.settings.clerk_api_key
        secret_key = secret_key.strip()
        if not secret_key:
            raise RuntimeError("CLERK_API_KEY not configured")
        return {
            "Authorization": f"Bearer {secret_key}",
            "Content-Type": "application/json",
        }

    def _get_resource_url(self, *, metadata: bool = False) -> str:
        base = f"{CLERK_API_BASE}/{self.resource_type}s/{self.resource_id}"
        if metadata:
            return f"{base}/metadata"
        return base

    async def get_public_metadata(self) -> dict:
        url = self._get_resource_url()
        headers = self._get_headers()
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            payload = response.json()
        public_metadata = payload.get("public_metadata")
        if isinstance(public_metadata, dict):
            return public_metadata
        return {}

    async def set_public_metadata(self, public_metadata: dict) -> None:
        url = self._get_resource_url(metadata=True)
        headers = self._get_headers()
        async with httpx.AsyncClient() as client:
            response = await client.patch(
                url,
                headers=headers,
                json={"public_metadata": public_metadata},
            )
            response.raise_for_status()

    async def update_public_metadata(self, updates: dict) -> dict:
        existing = await self.get_public_metadata()
        merged = self.merge_metadata(existing, updates)
        await self.set_public_metadata(merged)
        return merged
    

async def update_clerk_organization(
    *,
    org_id: str,
    public_metadata: dict | None = None,
    max_allowed_members: int | None = None,
) -> None:
    """Update a Clerk organization's public metadata and/or seat limit."""
    logger.info(f"Updating Clerk organization {org_id}: public_metadata={public_metadata}, max_allowed_members={max_allowed_members}")
    manager = ClerkPublicMetadataManager.for_organization(org_id)

    if public_metadata is not None:
        logger.info(f"Updating organization {org_id} public metadata: {public_metadata}")
        await manager.update_public_metadata(public_metadata)
        logger.info(f"Successfully updated organization {org_id} public metadata")

    if max_allowed_members is not None:
        logger.info(f"Updating organization {org_id} max_allowed_members to {max_allowed_members}")
        headers = manager._get_headers()
        url = manager._get_resource_url()
        async with httpx.AsyncClient() as client:
            response = await client.patch(
                url,
                headers=headers,
                json={"max_allowed_members": max_allowed_members},
            )
            response.raise_for_status()
        logger.info(f"Successfully updated organization {org_id} max_allowed_members to {max_allowed_members}")


async def update_clerk_user_metadata(
    *,
    clerk_user_id: str,
    public_metadata: dict,
) -> None:
    logger.info(f"Updating Clerk user {clerk_user_id} public metadata: {public_metadata}")
    manager = ClerkPublicMetadataManager(resource_type="user", resource_id=clerk_user_id)
    await manager.update_public_metadata(public_metadata)
    logger.info(f"Successfully updated Clerk user {clerk_user_id} public metadata")


def get_clerk_user_id_from_payload() -> str:
    payload = auth_header_ctx.get()
    if not payload or CLERK_JWT_SUB_KEY not in payload:
        logger.info("No Clerk user id found in payload")
        raise HTTPException(status_code=401, detail="Missing Clerk user id")
    return payload[CLERK_JWT_SUB_KEY]


def get_email_from_clerk_payload() -> str:
    payload = auth_header_ctx.get()
    if not payload:
        logger.info("No Clerk payload found in context")
        raise HTTPException(status_code=401, detail="Missing Clerk payload")

    email = payload.get(CLERK_JWT_EMAIL_KEY)
    logger.info(f"Clerk payload email: {email}")
    if not isinstance(email, str) or not email.strip():
        logger.info("No email found in Clerk payload")
        raise HTTPException(status_code=401, detail="Missing email in Clerk token")

    return email.strip()


async def get_paddle_customer_id_from_clerk_payload() -> str | None:
    """
    Retrieve paddle_customer_id directly from Clerk JWT public metadata.

    Assumes the JWT template includes:
    {
        "paddle_customer_id": "{{user.public_metadata.paddle_customer_id}}"
    }
    """
    payload = auth_header_ctx.get()
    if not payload:
        logger.warning("No Clerk payload in request context")
        return None

    customer_id = payload.get(PADDLE_CUSTOMER_ID_KEY)

    if isinstance(customer_id, str) and customer_id.strip():
        logger.debug(f"Resolved Paddle customer ID from JWT: {customer_id}")
        return customer_id

    logger.info(f"No {PADDLE_CUSTOMER_ID_KEY} found in Clerk JWT payload")
    return None


async def get_paddle_subscription_id_from_clerk_payload() -> str | None:
    payload = auth_header_ctx.get()
    if not payload:
        logger.info("No Clerk payload in request context for subscription ID")
        return None

    subscription_id = payload.get(PADDLE_SUBSCRIPTION_ID_KEY)
    if isinstance(subscription_id, str) and subscription_id.strip():
        logger.debug(f"Resolved Paddle subscription ID from JWT: {subscription_id}")
        return subscription_id.strip()
    logger.info(f"No {PADDLE_SUBSCRIPTION_ID_KEY} found in Clerk JWT payload")
    return None


async def get_organisation_created_by_from_clerk_payload() -> str | None:
    payload = auth_header_ctx.get()
    if not payload:
        logger.info("No Clerk payload in request context for organisation_created_by")
        return None

    created_by = payload.get(ORGANISATION_CREATED_BY_KEY)
    if isinstance(created_by, str) and created_by.strip():
        logger.debug(f"Resolved organisation_created_by from JWT: {created_by}")
        return created_by.strip()
    logger.info(f"No {ORGANISATION_CREATED_BY_KEY} found in Clerk JWT payload")
    return None


async def _get_jwks(issuer: str) -> dict[str, Any]:
    """Retrieve and cache JWKS for a Clerk issuer."""
    issuer = issuer.rstrip("/")
    if issuer not in _jwks_cache:
        url = f"{issuer}/.well-known/jwks.json"
        async with httpx.AsyncClient() as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()
        _jwks_cache[issuer] = {k["kid"]: k for k in data.get("keys", [])}
    return _jwks_cache[issuer]


async def verify_clerk_token(token: str) -> dict[str, Any]:
    """Verify a Clerk token, add a UUID derived from the Clerk ID, and return the payload."""
    try:
        unverified_header = jwt.get_unverified_header(token)
        unverified_claims = jwt.get_unverified_claims(token)
        issuer: str | None = unverified_claims.get("iss")
        kid: str | None = unverified_header.get("kid")
        if not issuer or not kid:
            msg = "Missing issuer or kid"
            raise JWTError(msg)
        jwks = await _get_jwks(issuer)
        key = jwks.get(kid)
        if not key:
            _jwks_cache.pop(issuer, None)  # force refresh
            jwks = await _get_jwks(issuer)
            key = jwks.get(kid)
            if not key:
                msg = "Public key not found"
                raise JWTError(msg)

        public_key = jwk.construct(key, unverified_header.get("alg", "RS256"))
        payload = jwt.decode(
            token,
            public_key,
            algorithms=[unverified_header.get("alg", "RS256")],
            audience=unverified_claims.get("aud"),
            issuer=issuer,
            # options={"verify_signature": False, "verify_aud": False, "verify_exp": False},
        )
        # ✅ Add deterministic UUID to the payload
        clerk_id = payload.get(CLERK_JWT_SUB_KEY)
        if not clerk_id:
            msg = f"Missing '{CLERK_JWT_SUB_KEY}' (Clerk ID) in token payload"
            raise JWTError(msg)
        payload[CLERK_JWT_UUID_KEY] = str(uuid.uuid5(uuid.NAMESPACE_DNS, str(clerk_id)))

        org = payload.get(CLERK_JWT_ORG_KEY)
        if isinstance(org, dict) and "id" in org:
            payload[ORG_ID_KEY] = org["id"]
        elif ORG_ID_KEY in payload:
            # Some Clerk tokens expose the organisation id directly
            payload[ORG_ID_KEY] = payload[ORG_ID_KEY]
        else:
            msg = "Missing organization info in Clerk token payload"
            raise JWTError(msg)
    except JWTError as exc:
        msg = "Invalid token"
        raise ValueError(msg) from exc
    return payload


def get_user_id_from_clerk_payload() -> UUID:
    """Extract the Clerk user UUID from the request context."""
    payload = auth_header_ctx.get()
    if not payload:
        raise HTTPException(status_code=401, detail="Missing Clerk payload")
    clerk_uuid = payload.get(CLERK_JWT_UUID_KEY)
    if not clerk_uuid:
        raise HTTPException(status_code=401, detail="Missing Clerk UUID")
    try:
        return UUID(clerk_uuid)
    except ValueError as err:
        raise HTTPException(
            status_code=401,
            detail="Invalid Clerk UUID format",
            headers={"WWW-Authenticate": "Bearer"},
        ) from err


def get_org_id_from_clerk_payload() -> str:
    payload = auth_header_ctx.get()
    if not payload:
        raise HTTPException(status_code=401, detail="Missing Clerk payload")
    org_id = payload.get(ORG_ID_KEY) if isinstance(payload, dict) else None
    if not org_id:
        raise HTTPException(status_code=401, detail="Missing organization in Clerk payload")
    if not isinstance(org_id, str):
        raise HTTPException(status_code=401, detail="Invalid organization identifier")
    return org_id


async def _apply_dummy_user_optins(
    new_user: User,
    session: AsyncSession | None,
) -> None:
    if session is None:
        logger.warning("[process_new_user_with_clerk] Session unavailable; skipping dummy optins lookup")
        return

    try:
        org_id = get_org_id_from_clerk_payload()
    except HTTPException:
        logger.warning("[process_new_user_with_clerk] Missing org_id in Clerk payload; skipping dummy optins lookup")
        return

    dummy_seed = DUMMY_USER_NAMESPACE_TEMPLATE.format(org_id=org_id)
    dummy_user_id = uuid5(NAMESPACE_URL, dummy_seed)
    dummy_user = await session.get(User, str(dummy_user_id))

    dummy_optins = dummy_user.optins if dummy_user and isinstance(dummy_user.optins, dict) else {}

    skip_trial_access = dummy_optins.get("skip_trial_access", False)
    trial_access_days = dummy_optins.get("trial_access_days", 7)
    trial_access_until = (datetime.now(timezone.utc) + timedelta(days=trial_access_days)).strftime("%Y-%m-%dT%H:%M:%SZ")

    new_user.optins = {
        **(new_user.optins or {}),
        "skip_trial_access": skip_trial_access,
        "trial_access_until": trial_access_until,
    }


async def process_new_user_with_clerk(new_user: User, session: AsyncSession | None = None):
    settings = get_settings_service().auth_settings
    # ✅ If Clerk is enabled, pull UUID from enriched auth_header_ctx payload
    if settings.CLERK_AUTH_ENABLED:
        user_id = get_user_id_from_clerk_payload()
        new_user.id = user_id
        logger.info(f"[process_new_user_with_clerk] Assigned Clerk UUID {new_user.id} to new user object")
        await _apply_dummy_user_optins(new_user, session)
        await _ensure_admin_superuser(new_user)


async def get_user_from_clerk_payload(db: AsyncSession) -> User:
    """Retrieve the current user using the payload stored in the request context."""
    user_id = get_user_id_from_clerk_payload()
    logger.debug(f"uuid_str: {user_id}")

    user = await get_user_by_id(db, user_id)
    logger.info(f"Retrieved user: {user}")
    if user is None:
        logger.info("User not found.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        logger.info(f"User {user.id} is inactive.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is inactive.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def _get_admin_email_from_env() -> str | None:
    settings_service = get_settings_service()
    website_domain = getattr(settings_service.settings, "website_domain", None)
    if not website_domain:
        return None
    return f"admin@{website_domain}".lower()


async def _ensure_admin_superuser(user: User) -> None:
    admin_email = _get_admin_email_from_env()
    if not admin_email:
        logger.debug("[ClerkAdmin] LANGFLOW_WEBSITE_DOMAIN/WEBSITE_DOMAIN not set; skipping admin promotion")
        return

    optins = getattr(user, "optins", None)
    if not isinstance(optins, dict):
        return

    optins_email = optins.get("email")
    if not optins_email:
        return

    if optins_email.lower() != admin_email:
        return

    if not user.is_superuser:
        user.is_superuser = True
        logger.info("[ClerkAdmin] Promoted %s to superuser based on admin email", user.username)


async def clerk_token_middleware(request: Request, call_next):
    """Middleware to handle Clerk JWT tokens and Langflow API keys."""
    settings = get_settings_service()
    if not settings.auth_settings.CLERK_AUTH_ENABLED:
        return await call_next(request)

    ctx_token: Token | None = None

    try:
        # 1️⃣ Clerk JWT
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[len("Bearer ") :]

            try:
                payload = await verify_clerk_token(token)
            except Exception as exc:  # noqa: BLE001
                logger.warning(f"[ClerkMiddleware] Failed to verify Clerk token: {exc}")
                return JSONResponse(
                    status_code=HTTP_401_UNAUTHORIZED,
                    content={"detail": "Invalid Clerk token"},
                )

            ctx_token = auth_header_ctx.set(payload)
            return await call_next(request)

        # 2️⃣ API Key
        api_key_header = request.headers.get("x-api-key")
        if api_key_header:
            from langflow.services.auth.api_key_codec import decode_api_key

            decoded = decode_api_key(api_key_header)
            if not decoded.is_encoded or not decoded.organization_id:
                logger.warning("[ClerkMiddleware] Invalid or unscoped API key")
                return JSONResponse(
                    status_code=HTTP_401_UNAUTHORIZED,
                    content={"detail": "Invalid or unscoped API key"},
                )

            ctx_token = auth_header_ctx.set(
                {
                    ORG_ID_KEY: decoded.organization_id,
                    CLERK_JWT_UUID_KEY: decoded.user_id,
                }
            )
            return await call_next(request)

        # 3️⃣ No auth → pass through
        return await call_next(request)

    finally:
        if ctx_token is not None:
            auth_header_ctx.reset(ctx_token)
        else:
            auth_header_ctx.set(None)
