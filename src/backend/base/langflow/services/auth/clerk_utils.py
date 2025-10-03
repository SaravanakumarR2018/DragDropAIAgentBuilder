import uuid
from contextvars import ContextVar, Token
from typing import Any
from uuid import UUID

import httpx
from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from jose import JWTError, jwk, jwt
from sqlmodel.ext.asyncio.session import AsyncSession
from starlette.status import HTTP_401_UNAUTHORIZED

from langflow.logging.logger import logger
from langflow.services.database.models.user import User
from langflow.services.database.models.user.crud import get_user_by_id
from langflow.services.deps import get_settings_service

from .clerk_debug import clerk_debug_log, register_clerk_debug_signal_handlers

# Context variable to store decoded clerk claims per request
auth_header_ctx: ContextVar[dict | None] = ContextVar("auth_header_ctx", default=None)

_jwks_cache: dict[str, dict[str, Any]] = {}


register_clerk_debug_signal_handlers()


async def _get_jwks(issuer: str) -> dict[str, Any]:
    """Retrieve and cache JWKS for a Clerk issuer."""
    issuer = issuer.rstrip("/")
    clerk_debug_log("[_get_jwks] Normalized issuer: %s", issuer)
    if issuer not in _jwks_cache:
        clerk_debug_log("[_get_jwks] Cache miss for issuer %s. Fetching JWKS.", issuer)
        url = f"{issuer}/.well-known/jwks.json"
        async with httpx.AsyncClient() as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()
        _jwks_cache[issuer] = {k["kid"]: k for k in data.get("keys", [])}
        clerk_debug_log(
            "[_get_jwks] Cached %s keys for issuer %s", len(_jwks_cache[issuer]), issuer
        )
    else:
        clerk_debug_log("[_get_jwks] Cache hit for issuer %s", issuer)
    return _jwks_cache[issuer]


async def verify_clerk_token(token: str) -> dict[str, Any]:
    """Verify a Clerk token, add a UUID derived from the Clerk ID, and return the payload."""
    clerk_debug_log("[verify_clerk_token] Raw token received: %s", token)
    try:
        unverified_header = jwt.get_unverified_header(token)
        unverified_claims = jwt.get_unverified_claims(token)
        clerk_debug_log("[verify_clerk_token] Unverified header: %s", unverified_header)
        clerk_debug_log("[verify_clerk_token] Unverified claims: %s", unverified_claims)
        issuer: str | None = unverified_claims.get("iss")
        kid: str | None = unverified_header.get("kid")
        if not issuer or not kid:
            msg = "Missing issuer or kid"
            raise JWTError(msg)
        clerk_debug_log("[verify_clerk_token] Using issuer=%s kid=%s", issuer, kid)
        jwks = await _get_jwks(issuer)
        key = jwks.get(kid)
        if not key:
            _jwks_cache.pop(issuer, None)  # force refresh
            jwks = await _get_jwks(issuer)
            key = jwks.get(kid)
            if not key:
                msg = "Public key not found"
                raise JWTError(msg)
        clerk_debug_log("[verify_clerk_token] Resolved JWK: %s", key)

        public_key = jwk.construct(key, unverified_header.get("alg", "RS256"))
        clerk_debug_log(
            "[verify_clerk_token] Constructed public key with alg=%s",
            unverified_header.get("alg", "RS256"),
        )
        payload = jwt.decode(
            token,
            public_key,
            algorithms=[unverified_header.get("alg", "RS256")],
            audience=unverified_claims.get("aud"),
            issuer=issuer,
            # options={"verify_signature": False, "verify_aud": False, "verify_exp": False},
        )
        clerk_debug_log("[verify_clerk_token] Decoded payload: %s", payload)
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
        clerk_debug_log("[verify_clerk_token] Final payload with UUID & org: %s", payload)
    except JWTError as exc:
        msg = "Invalid token"
        clerk_debug_log("[verify_clerk_token] Token validation failed: %s", exc)
        raise ValueError(msg) from exc
    return payload


def get_user_id_from_clerk_payload() -> UUID:
    """Extract the Clerk user UUID from the request context."""
    payload = auth_header_ctx.get()
    clerk_debug_log("[get_user_id_from_clerk_payload] auth_header_ctx payload: %s", payload)
    if not payload:
        clerk_debug_log("[get_user_id_from_clerk_payload] Missing payload")
        raise HTTPException(status_code=401, detail="Missing Clerk payload")
    clerk_uuid = payload.get("uuid")
    if not clerk_uuid:
        clerk_debug_log("[get_user_id_from_clerk_payload] Missing Clerk UUID in payload")
        raise HTTPException(status_code=401, detail="Missing Clerk UUID")
    try:
        clerk_debug_log(
            "[get_user_id_from_clerk_payload] Converting Clerk UUID string %s to UUID", clerk_uuid
        )
        return UUID(clerk_uuid)
    except ValueError as err:
        clerk_debug_log(
            "[get_user_id_from_clerk_payload] Invalid Clerk UUID format encountered: %s", err
        )
        raise HTTPException(
            status_code=401,
            detail="Invalid Clerk UUID format",
            headers={"WWW-Authenticate": "Bearer"},
        ) from err


async def process_new_user_with_clerk(new_user: User):
    settings = get_settings_service().auth_settings
    # ✅ If Clerk is enabled, pull UUID from enriched auth_header_ctx payload
    if settings.CLERK_AUTH_ENABLED:
        clerk_debug_log(
            "[process_new_user_with_clerk] Clerk auth enabled. Preparing to assign UUID to new user %s",
            new_user,
        )
        user_id = get_user_id_from_clerk_payload()
        new_user.id = user_id
        logger.info(f"[process_new_user_with_clerk] Assigned Clerk UUID {new_user.id} to new user object")
        clerk_debug_log(
            "[process_new_user_with_clerk] Assigned UUID %s to new user", new_user.id
        )


async def get_user_from_clerk_payload(db: AsyncSession) -> User:
    """Retrieve the current user using the payload stored in the request context."""
    user_id = get_user_id_from_clerk_payload()
    clerk_debug_log("[get_user_from_clerk_payload] Looking up user_id: %s", user_id)
    logger.debug(f"uuid_str: {user_id}")

    user = await get_user_by_id(db, user_id)
    logger.info(f"Retrieved user: {user}")
    clerk_debug_log("[get_user_from_clerk_payload] Retrieved user: %s", user)
    if user is None:
        logger.info("User not found.")
        clerk_debug_log("[get_user_from_clerk_payload] User not found for user_id %s", user_id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        logger.info(f"User {user.id} is inactive.")
        clerk_debug_log("[get_user_from_clerk_payload] User %s is inactive", user.id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is inactive.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    clerk_debug_log("[get_user_from_clerk_payload] Returning active user %s", user.id)
    return user


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
        clerk_debug_log("[clerk_token_middleware] Authorization header: %s", auth_header)
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[len("Bearer ") :]
            try:
                clerk_debug_log("[clerk_token_middleware] Attempting Clerk token verification")
                payload = await verify_clerk_token(token)
                ctx_token = auth_header_ctx.set(payload)
                clerk_debug_log("[clerk_token_middleware] Clerk token verified. Payload: %s", payload)
                response = await call_next(request)
            except Exception as exc:  # noqa: BLE001

                logger.warning(f"[ClerkMiddleware] Failed to verify Clerk token: {exc}")
                clerk_debug_log(
                    "[clerk_token_middleware] Clerk token verification failed: %s", exc
                )
                response = JSONResponse(
                    status_code=HTTP_401_UNAUTHORIZED,
                    content={"detail": "Invalid Clerk token"},
                )

        # 2️⃣ API Key
        elif (api_key_header := request.headers.get("x-api-key")):

            from langflow.services.auth.api_key_codec import decode_api_key

            clerk_debug_log("[clerk_token_middleware] API key header received: %s", api_key_header)
            decoded = decode_api_key(api_key_header)
            if not decoded.is_encoded or not decoded.organization_id:
                logger.warning(f"[ClerkMiddleware] Invalid or unscoped API key: {api_key_header}")
                clerk_debug_log(
                    "[clerk_token_middleware] API key decoding failed: %s", decoded
                )
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
                clerk_debug_log(
                    "[clerk_token_middleware] API key decoded. Context payload: %s",
                    context_payload,
                )
                response = await call_next(request)

        # 3️⃣ No auth header → pass through
        else:
            clerk_debug_log("[clerk_token_middleware] No auth header provided")
            response = await call_next(request)

    finally:
        clerk_debug_log(
            "[clerk_token_middleware] auth_header_ctx payload before reset: %s",
            auth_header_ctx.get(),
        )
        if ctx_token is not None:
            auth_header_ctx.reset(ctx_token)
        else:
            auth_header_ctx.set(None)
        clerk_debug_log(
            "[clerk_token_middleware] auth_header_ctx payload after reset: %s",
            auth_header_ctx.get(),
        )
        clerk_debug_log("[clerk_token_middleware] Final response status: %s", getattr(response, "status_code", None))
    return response
