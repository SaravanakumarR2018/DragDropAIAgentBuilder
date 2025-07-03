from contextvars import ContextVar
from typing import Any
import uuid

import httpx
from jose import JWTError, jwk, jwt
from loguru import logger
from fastapi import HTTPException, Request, status
from uuid import UUID
from loguru import logger
from langflow.services.deps import get_settings_service
from langflow.services.database.models.user import UserCreate, User
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.services.database.models.user.crud import get_user_by_id
from langflow.services.database.models.user.model import User

# Context variable to store decoded clerk claims per request
auth_header_ctx: ContextVar[dict | None] = ContextVar("auth_header_ctx", default=None)

_jwks_cache: dict[str, dict[str, Any]] = {}


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
            raise JWTError("Missing issuer or kid")

        jwks = await _get_jwks(issuer)
        key = jwks.get(kid)
        if not key:
            _jwks_cache.pop(issuer, None)  # force refresh
            jwks = await _get_jwks(issuer)
            key = jwks.get(kid)
            if not key:
                raise JWTError("Public key not found")

        public_key = jwk.construct(key, unverified_header.get("alg", "RS256"))
        payload = jwt.decode(
            token,
            public_key,
            algorithms=[unverified_header.get("alg", "RS256")],
            audience=unverified_claims.get("aud"),
            issuer=issuer
        )
        # ✅ Add deterministic UUID to the payload
        clerk_id = payload.get("sub")
        if not clerk_id:
            raise JWTError("Missing 'sub' (Clerk ID) in token payload")
        payload["uuid"] = str(uuid.uuid5(uuid.NAMESPACE_DNS, str(clerk_id)))

    except JWTError as exc:
        raise ValueError("Invalid token") from exc

    return payload
 
async def process_new_user_with_clerk(user: UserCreate, new_user: User):
    settings = get_settings_service().auth_settings
    # ✅ If Clerk is enabled, pull UUID from enriched auth_header_ctx payload
    if settings.CLERK_AUTH_ENABLED:
        payload = auth_header_ctx.get()
        if not payload:
            raise HTTPException(status_code=401, detail="Missing Clerk payload")
        clerk_uuid = payload.get("uuid")
        if not clerk_uuid:
            raise HTTPException(status_code=401, detail="Missing Clerk UUID")
        new_user.id = UUID(clerk_uuid)
        logger.info(new_user.id)

async def get_user_from_clerk_payload(token: str, db: AsyncSession) -> User:
    """Retrieve the current user using the payload from ``verify_clerk_token``."""
    try:
        payload = await verify_clerk_token(token)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    uuid_str = payload.get("uuid")
    logger.info(f"uuid_str: {uuid_str}")
    if not uuid_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Clerk UUID",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        user_id = UUID(uuid_str)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Clerk UUID format",
            headers={"WWW-Authenticate": "Bearer"},
        )

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
 
async def create_context_var_for_api(request: Request) -> None:
    """Extracts and verifies Clerk token from request and sets it in context variable if Clerk auth is enabled."""
    settings = get_settings_service()
 
    if not settings.auth_settings.CLERK_AUTH_ENABLED:
        return
 
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header"
        )
 
    token = auth_header[len("Bearer "):]
    try:
        payload = await verify_clerk_token(token)
        auth_header_ctx.set(payload)     # Set new context
        logger.info(f"Clerk token verified: {payload}")
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed"
        ) from exc