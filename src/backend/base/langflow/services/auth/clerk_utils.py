import uuid
from datetime import datetime, timedelta, timezone
from contextvars import ContextVar, Token
from typing import Any
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

# Context variable to store decoded clerk claims per request
auth_header_ctx: ContextVar[dict | None] = ContextVar("auth_header_ctx", default=None)

_jwks_cache: dict[str, dict[str, Any]] = {}

CLERK_API_BASE = "https://api.clerk.com/v1"

async def update_clerk_private_metadata(
    *,
    clerk_user_id: str,
    private_metadata: dict,
) -> None:
    settings_service = get_settings_service()
    secret_key = settings_service.settings.clerk_api_key

    if not secret_key:
        raise RuntimeError("CLERK_API_KEY not configured")

    url = f"{CLERK_API_BASE}/users/{clerk_user_id}/metadata"

    headers = {
        "Authorization": f"Bearer {secret_key}",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient() as client:
        response = await client.patch(
            url,
            headers=headers,
            json={"private_metadata": private_metadata},
        )
        response.raise_for_status()


def get_clerk_user_id_from_payload() -> str:
    payload = auth_header_ctx.get()
    if not payload or "sub" not in payload:
        logger.info("No Clerk user id found in payload")
        raise HTTPException(status_code=401, detail="Missing Clerk user id")
    return payload["sub"]


def get_email_from_clerk_payload() -> str:
    payload = auth_header_ctx.get()
    if not payload:
        logger.info("No Clerk payload found in context")
        raise HTTPException(status_code=401, detail="Missing Clerk payload")

    email = payload.get("email")
    logger.info(f"Clerk payload email: {email}")
    if not isinstance(email, str) or not email.strip():
        logger.info("No email found in Clerk payload")
        logger.info("Missing email in Clerk token")

    return email


async def get_paddle_customer_id_from_clerk_payload() -> str | None:
    """
    Retrieve paddle_customer_id for the current user.

    Order of resolution:
    1. JWT payload (if injected via public_metadata / JWT template)
    2. Clerk private_metadata via Clerk API (server-side)
    """

    payload = auth_header_ctx.get()
    if not payload:
        logger.warning("No Clerk payload in request context")
        return None

    #Secure path: fetch from Clerk private_metadata
    try:
        clerk_user_id = get_clerk_user_id_from_payload()
    except HTTPException:
        logger.warning("Unable to resolve Clerk user id from payload")
        return None

    settings_service = get_settings_service()
    secret_key = settings_service.settings.clerk_api_key

    if not secret_key:
        logger.error("CLERK_API_KEY not configured")
        return None

    url = f"{CLERK_API_BASE}/users/{clerk_user_id}"
    headers = {
        "Authorization": f"Bearer {secret_key}",
        "Content-Type": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            user_data = response.json()
    except Exception as exc:
        logger.error(
            f"Failed to fetch Clerk user {clerk_user_id} from Clerk API: {exc}"
        )
        return None

    private_metadata = user_data.get("private_metadata") or {}
    customer_id = private_metadata.get("paddle_customer_id")

    if isinstance(customer_id, str) and customer_id.strip():
        return customer_id

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
        logger.info(f"Clerk token payload before enrichment: {payload}")
        # ✅ Add deterministic UUID to the payload
        clerk_id = payload.get("sub")
        if not clerk_id:
            msg = "Missing 'sub' (Clerk ID) in token payload"
            raise JWTError(msg)
        payload["uuid"] = str(uuid.uuid5(uuid.NAMESPACE_DNS, str(clerk_id)))

        org = payload.get("o")
        if isinstance(org, dict) and "id" in org:
            payload["org_id"] = org["id"]
        elif "org_id" in payload:
            # Some Clerk tokens expose the organisation id directly
            payload["org_id"] = payload["org_id"]
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
    clerk_uuid = payload.get("uuid")
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
    org_id = payload.get("org_id") if isinstance(payload, dict) else None
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
    response = None

    try:
        # 1️⃣ Clerk JWT
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[len("Bearer ") :]
            try:
                payload = await verify_clerk_token(token)
                logger.info(f"[ClerkMiddleware] Decoded token payload: {payload}")
                ctx_token = auth_header_ctx.set(payload)
                response = await call_next(request)
            except Exception as exc:  # noqa: BLE001

                logger.warning(f"[ClerkMiddleware] Failed to verify Clerk token: {exc}")
                response = JSONResponse(
                    status_code=HTTP_401_UNAUTHORIZED,
                    content={"detail": "Invalid Clerk token"},
                )

        # 2️⃣ API Key
        elif (api_key_header := request.headers.get("x-api-key")):

            from langflow.services.auth.api_key_codec import decode_api_key

            decoded = decode_api_key(api_key_header)
            if not decoded.is_encoded or not decoded.organization_id:
                logger.warning(f"[ClerkMiddleware] Invalid or unscoped API key: {api_key_header}")
                response = JSONResponse(
                    status_code=HTTP_401_UNAUTHORIZED,
                    content={"detail": "Invalid or unscoped API key"},
                )
            else:
                context_payload = {
                    "org_id": decoded.organization_id,
                    "uuid": decoded.user_id,
                }
                ctx_token = auth_header_ctx.set(context_payload)
                response = await call_next(request)

        # 3️⃣ No auth header → pass through
        else:
            response = await call_next(request)

    finally:
        if ctx_token is not None:
            auth_header_ctx.reset(ctx_token)
        else:
            auth_header_ctx.set(None)
    return response
