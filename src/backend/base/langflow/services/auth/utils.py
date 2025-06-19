import base64
import random
import warnings
from collections.abc import Coroutine
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from cryptography.fernet import Fernet
from fastapi import Depends, HTTPException, Security, WebSocketException, status
from fastapi.security import APIKeyHeader, APIKeyQuery, OAuth2PasswordBearer
# Add a comment about the clerk-python dependency
# To enable Clerk authentication, ensure 'clerk-python' is added to your project dependencies.
from jose import JWTError, jwt
from loguru import logger
from sqlmodel.ext.asyncio.session import AsyncSession

try:
    # For Clerk integration (optional dependency)
    from clerk_sdk.clerk import Clerk
    # from clerk_sdk.client import ClerkClient # ClerkClient might be part of Clerk or used differently
    # Depending on the version of clerk_sdk, Clerk() might be the main interface.
    # Example: clerk = Clerk(secret_key="...", publishable_key="...")
    # or clerk = Clerk() and then use clerk.verify_token(token, ...)
    # For newer versions, it might be:
    # from clerk_sdk.clerk_instance_manager import ClerkInstanceManager
    # ClerkInstanceManager.get_instance().verify_token(token)
    # Or using specific verification functions with JWKS.
    clerk_available = True
except ImportError:
    clerk_available = False
    Clerk = None # Define Clerk as None if not available, for type hinting or conditional checks

from langflow.services.settings.auth import AuthSettings # Added import
from starlette.websockets import WebSocket

from langflow.services.database.models.api_key.crud import check_key
from langflow.services.database.models.user.crud import get_user_by_id, get_user_by_username, update_user_last_login_at
from langflow.services.database.models.user.model import User, UserRead
from langflow.services.deps import get_db_service, get_session, get_settings_service
from langflow.services.settings.service import SettingsService

if TYPE_CHECKING:
    from langflow.services.database.models.api_key.model import ApiKey

oauth2_login = OAuth2PasswordBearer(tokenUrl="api/v1/login", auto_error=False)

API_KEY_NAME = "x-api-key"

api_key_query = APIKeyQuery(name=API_KEY_NAME, scheme_name="API key query", auto_error=False)
api_key_header = APIKeyHeader(name=API_KEY_NAME, scheme_name="API key header", auto_error=False)

MINIMUM_KEY_LENGTH = 32


# Source: https://github.com/mrtolkien/fastapi_simple_security/blob/master/fastapi_simple_security/security_api_key.py
async def api_key_security(
    query_param: Annotated[str, Security(api_key_query)],
    header_param: Annotated[str, Security(api_key_header)],
) -> UserRead | None:
    settings_service = get_settings_service()
    result: ApiKey | User | None

    async with get_db_service().with_session() as db:
        if settings_service.auth_settings.AUTO_LOGIN:
            # Get the first user
            if not settings_service.auth_settings.SUPERUSER:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Missing first superuser credentials",
                )
            warnings.warn(
                (
                    "In v1.5, the default behavior of AUTO_LOGIN authentication will change to require a valid API key"
                    " or JWT. If you integrated with Langflow prior to v1.5, make sure to update your code to pass an "
                    "API key or JWT when authenticating with protected endpoints."
                ),
                DeprecationWarning,
                stacklevel=2,
            )
            if query_param or header_param:
                result = await check_key(db, query_param or header_param)
            else:
                result = await get_user_by_username(db, settings_service.auth_settings.SUPERUSER)

        elif not query_param and not header_param:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="An API key must be passed as query or header",
            )

        elif query_param:
            result = await check_key(db, query_param)

        else:
            result = await check_key(db, header_param)

        if not result:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid or missing API key",
            )
        if isinstance(result, User):
            return UserRead.model_validate(result, from_attributes=True)
    msg = "Invalid result type"
    raise ValueError(msg)


async def ws_api_key_security(
    api_key: str | None,
) -> UserRead:
    settings = get_settings_service()
    async with get_db_service().with_session() as db:
        if settings.auth_settings.AUTO_LOGIN:
            if not settings.auth_settings.SUPERUSER:
                # internal server misconfiguration
                raise WebSocketException(
                    code=status.WS_1011_INTERNAL_ERROR,
                    reason="Missing first superuser credentials",
                )
            warnings.warn(
                ("In v1.5, AUTO_LOGIN will *require* a valid API key or JWT. Please update your clients accordingly."),
                DeprecationWarning,
                stacklevel=2,
            )
            if api_key:
                result = await check_key(db, api_key)
            else:
                result = await get_user_by_username(db, settings.auth_settings.SUPERUSER)

        # normal path: must provide an API key
        else:
            if not api_key:
                raise WebSocketException(
                    code=status.WS_1008_POLICY_VIOLATION,
                    reason="An API key must be passed as query or header",
                )
            result = await check_key(db, api_key)

        # key was invalid or missing
        if not result:
            raise WebSocketException(
                code=status.WS_1008_POLICY_VIOLATION,
                reason="Invalid or missing API key",
            )

        # convert SQL-model User → pydantic UserRead
        if isinstance(result, User):
            return UserRead.model_validate(result, from_attributes=True)

    # fallback: something unexpected happened
    raise WebSocketException(
        code=status.WS_1011_INTERNAL_ERROR,
        reason="Authentication subsystem error",
    )


async def get_current_user(
    token: Annotated[str, Security(oauth2_login)],
    query_param: Annotated[str, Security(api_key_query)],
    header_param: Annotated[str, Security(api_key_header)],
    db: Annotated[AsyncSession, Depends(get_session)],
) -> User:
    if token:
        return await get_current_user_by_jwt(token, db)
    user = await api_key_security(query_param, header_param)
    if user:
        return user

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Invalid or missing API key",
    )


async def get_current_user_by_jwt(
    token: str,
    db: AsyncSession,
) -> User:
    settings_service = get_settings_service()
    auth_settings: AuthSettings = settings_service.auth_settings # Explicit type

    # User model consideration comment:
    # To fully map Clerk users to Langflow users, a new field like `clerk_user_id: Optional[str]`
    # might be needed in the `langflow.services.database.models.user.model.User` SQLModel.

    if auth_settings.CLERK_AUTH_ENABLED:
        if clerk_available and Clerk is not None: # Check if Clerk SDK was imported
            try:
                # Placeholder for Clerk token validation
                logger.debug("Attempting Clerk token validation.")
                # 1. Initialize Clerk client (if needed, depends on SDK version and setup)
                #    Example:
                #    clerk_instance = Clerk(secret_key=auth_settings.CLERK_SECRET_KEY.get_secret_value() if auth_settings.CLERK_SECRET_KEY else None,
                #                           publishable_key=auth_settings.CLERK_PUBLISHABLE_KEY)
                #    Or, if using a global instance:
                #    clerk_instance = Clerk() # Assuming it's configured globally
                #
                # 2. Verify token using Clerk SDK
                #    The exact method depends on the Clerk SDK version.
                #    It might be something like:
                #    clerk_payload = clerk_instance.verify_token(token, jwt_key=auth_settings.CLERK_SECRET_KEY.get_secret_value() if auth_settings.CLERK_SECRET_KEY else None) # if using symmetric key
                #    or using JWKS for asymmetric verification if CLERK_JWT_VERIFICATION_TEMPLATE is used.
                #    For example, if CLERK_JWT_VERIFICATION_TEMPLATE points to a JWKS URL:
                #    # decoded_token = jwt.decode(token, key=jwks_client.get_signing_key_from_jwt(token).key, algorithms=["RS256"], audience="...", issuer="...")
                #    # This part needs to be implemented based on Clerk's Python SDK documentation for stateless verification.
                #
                #    For now, this is a placeholder. If you have a valid Clerk token,
                #    the following lines would be replaced with actual verification.
                #    Let's assume `clerk_payload` is the result of successful verification.

                # Mocking a successful Clerk validation for structure demonstration (REMOVE THIS IN ACTUAL IMPLEMENTATION)
                # if token.startswith("clk_"): # A dummy check
                #    clerk_user_id = "user_clerk_123" # Extracted from actual clerk_payload.sub or similar
                #    logger.info(f"Clerk token validated for Clerk user ID: {clerk_user_id}")
                #
                #    # 3. Find or create Langflow user
                #    #    langflow_user = await get_user_by_clerk_id(db, clerk_user_id) # Hypothetical function
                #    #    if not langflow_user:
                #    #        logger.info(f"No Langflow user found for Clerk ID {clerk_user_id}. Creating new user.")
                #    #        # user_email = clerk_payload.get("email") # Or other details
                #    #        # langflow_user = await create_user_from_clerk(db, clerk_user_id, user_email) # Hypothetical
                #    #    if langflow_user and langflow_user.is_active:
                #    #        return langflow_user
                # else:
                #    raise JWTError("Not a valid Clerk token (dummy check).") # End of dummy check

                # If Clerk validation is successful and a Langflow user is found/created:
                # return langflow_user
                # For this subtask, we'll just log and fall through if actual verification isn't implemented.
                logger.warning("Clerk token validation logic is a placeholder. Falling back to Langflow JWT.")

            except JWTError as e:
                logger.debug(f"Clerk JWTError during token validation: {e}. Falling back to Langflow JWT.")
            except Exception as e:
                logger.error(f"An unexpected error occurred during Clerk token validation: {e}. Falling back to Langflow JWT.")
        else:
            logger.warning("Clerk authentication is enabled, but the Clerk SDK is not available. Falling back to Langflow JWT.")


    # Original Langflow Token Validation (executes if Clerk is disabled, or if Clerk validation fails/is skipped)
    if isinstance(token, Coroutine):
        token = await token

    secret_key = auth_settings.SECRET_KEY.get_secret_value()
    if secret_key is None:
        logger.error("Secret key is not set in settings for Langflow JWT validation.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failure: Langflow JWT secret key not configured.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        logger.debug("Attempting Langflow JWT token validation.")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            payload = jwt.decode(token, secret_key, algorithms=[auth_settings.ALGORITHM])
        user_id: UUID = payload.get("sub")  # type: ignore[assignment]
        token_type: str = payload.get("type")  # type: ignore[assignment] # Should be "access"
        if expires := payload.get("exp", None):
            expires_datetime = datetime.fromtimestamp(expires, timezone.utc)
            if datetime.now(timezone.utc) > expires_datetime:
                logger.info(f"Langflow JWT token expired for user ID: {user_id}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has expired.",
                    headers={"WWW-Authenticate": "Bearer"},
                )

        if user_id is None or token_type != "access": # Ensure it's an access token
            logger.info(f"Invalid Langflow JWT token payload. User ID: {user_id}, Token type: {token_type}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token details (not an access token or missing user ID).",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except JWTError as e:
        logger.debug(f"Langflow JWT validation failed: {e}")
        # This exception will be raised if Clerk auth was enabled but failed, and then Langflow auth also failed.
        # Or if Clerk auth was disabled and Langflow auth failed.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials (Langflow JWT).",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e

    user = await get_user_by_id(db, user_id)
    if user is None or not user.is_active:
        logger.info(f"Langflow user not found or inactive for ID: {user_id}.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or is inactive (Langflow).",
            headers={"WWW-Authenticate": "Bearer"},
        )
    logger.debug(f"Successfully validated Langflow JWT for user: {user.username}")
    return user


async def get_current_user_for_websocket(
    websocket: WebSocket,
    db: AsyncSession,
) -> User | UserRead:
    token = websocket.cookies.get("access_token_lf") or websocket.query_params.get("token")
    if token:
        user = await get_current_user_by_jwt(token, db)
        if user:
            return user

    api_key = (
        websocket.query_params.get("x-api-key")
        or websocket.query_params.get("api_key")
        or websocket.headers.get("x-api-key")
        or websocket.headers.get("api_key")
    )
    if api_key:
        user_read = await ws_api_key_security(api_key)
        if user_read:
            return user_read

    raise WebSocketException(
        code=status.WS_1008_POLICY_VIOLATION, reason="Missing or invalid credentials (cookie, token or API key)."
    )


async def get_current_active_user(current_user: Annotated[User, Depends(get_current_user)]):
    if not current_user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inactive user")
    return current_user


async def get_current_active_superuser(current_user: Annotated[User, Depends(get_current_user)]) -> User:
    if not current_user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inactive user")
    if not current_user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="The user doesn't have enough privileges")
    return current_user


def verify_password(plain_password, hashed_password):
    settings_service = get_settings_service()
    return settings_service.auth_settings.pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    settings_service = get_settings_service()
    return settings_service.auth_settings.pwd_context.hash(password)


def create_token(data: dict, expires_delta: timedelta):
    settings_service = get_settings_service()

    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode["exp"] = expire

    return jwt.encode(
        to_encode,
        settings_service.auth_settings.SECRET_KEY.get_secret_value(),
        algorithm=settings_service.auth_settings.ALGORITHM,
    )


async def create_super_user(
    username: str,
    password: str,
    db: AsyncSession,
) -> User:
    super_user = await get_user_by_username(db, username)

    if not super_user:
        super_user = User(
            username=username,
            password=get_password_hash(password),
            is_superuser=True,
            is_active=True,
            last_login_at=None,
        )

        db.add(super_user)
        await db.commit()
        await db.refresh(super_user)

    return super_user


async def create_user_longterm_token(db: AsyncSession) -> tuple[UUID, dict]:
    settings_service = get_settings_service()

    username = settings_service.auth_settings.SUPERUSER
    super_user = await get_user_by_username(db, username)
    if not super_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Super user hasn't been created")
    access_token_expires_longterm = timedelta(days=365)
    access_token = create_token(
        data={"sub": str(super_user.id), "type": "access"},
        expires_delta=access_token_expires_longterm,
    )

    # Update: last_login_at
    await update_user_last_login_at(super_user.id, db)

    return super_user.id, {
        "access_token": access_token,
        "refresh_token": None,
        "token_type": "bearer",
    }


def create_user_api_key(user_id: UUID) -> dict:
    access_token = create_token(
        data={"sub": str(user_id), "type": "api_key"},
        expires_delta=timedelta(days=365 * 2),
    )

    return {"api_key": access_token}


def get_user_id_from_token(token: str) -> UUID:
    try:
        user_id = jwt.get_unverified_claims(token)["sub"]
        return UUID(user_id)
    except (KeyError, JWTError, ValueError):
        return UUID(int=0)


async def create_user_tokens(user_id: UUID, db: AsyncSession, *, update_last_login: bool = False) -> dict:
    settings_service = get_settings_service()

    access_token_expires = timedelta(seconds=settings_service.auth_settings.ACCESS_TOKEN_EXPIRE_SECONDS)
    access_token = create_token(
        data={"sub": str(user_id), "type": "access"},
        expires_delta=access_token_expires,
    )

    refresh_token_expires = timedelta(seconds=settings_service.auth_settings.REFRESH_TOKEN_EXPIRE_SECONDS)
    refresh_token = create_token(
        data={"sub": str(user_id), "type": "refresh"},
        expires_delta=refresh_token_expires,
    )

    # Update: last_login_at
    if update_last_login:
        await update_user_last_login_at(user_id, db)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


async def create_refresh_token(refresh_token: str, db: AsyncSession):
    settings_service = get_settings_service()

    try:
        # Ignore warning about datetime.utcnow
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            payload = jwt.decode(
                refresh_token,
                settings_service.auth_settings.SECRET_KEY.get_secret_value(),
                algorithms=[settings_service.auth_settings.ALGORITHM],
            )
        user_id: UUID = payload.get("sub")  # type: ignore[assignment]
        token_type: str = payload.get("type")  # type: ignore[assignment]

        if user_id is None or token_type == "":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

        user_exists = await get_user_by_id(db, user_id)

        if user_exists is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

        return await create_user_tokens(user_id, db)

    except JWTError as e:
        logger.exception("JWT decoding error")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        ) from e


async def authenticate_user(username: str, password: str, db: AsyncSession) -> User | None:
    user = await get_user_by_username(db, username)

    if not user:
        return None

    if not user.is_active:
        if not user.last_login_at:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Waiting for approval")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inactive user")

    return user if verify_password(password, user.password) else None


def add_padding(s):
    # Calculate the number of padding characters needed
    padding_needed = 4 - len(s) % 4
    return s + "=" * padding_needed


def ensure_valid_key(s: str) -> bytes:
    # If the key is too short, we'll use it as a seed to generate a valid key
    if len(s) < MINIMUM_KEY_LENGTH:
        # Use the input as a seed for the random number generator
        random.seed(s)
        # Generate 32 random bytes
        key = bytes(random.getrandbits(8) for _ in range(32))
        key = base64.urlsafe_b64encode(key)
    else:
        key = add_padding(s).encode()
    return key


def get_fernet(settings_service: SettingsService):
    secret_key: str = settings_service.auth_settings.SECRET_KEY.get_secret_value()
    valid_key = ensure_valid_key(secret_key)
    return Fernet(valid_key)


def encrypt_api_key(api_key: str, settings_service: SettingsService):
    fernet = get_fernet(settings_service)
    # Two-way encryption
    encrypted_key = fernet.encrypt(api_key.encode())
    return encrypted_key.decode()


def decrypt_api_key(encrypted_api_key: str, settings_service: SettingsService):
    """Decrypt the provided encrypted API key using Fernet decryption.

    This function first attempts to decrypt the API key by encoding it,
    assuming it is a properly encoded string. If that fails, it logs a detailed
    debug message including the exception information and retries decryption
    using the original string input.

    Args:
        encrypted_api_key (str): The encrypted API key.
        settings_service (SettingsService): Service providing authentication settings.

    Returns:
        str: The decrypted API key, or an empty string if decryption cannot be performed.
    """
    fernet = get_fernet(settings_service)
    if isinstance(encrypted_api_key, str):
        try:
            return fernet.decrypt(encrypted_api_key.encode()).decode()
        except Exception as primary_exception:  # noqa: BLE001
            logger.debug(
                "Decryption using UTF-8 encoded API key failed. Error: %s. "
                "Retrying decryption using the raw string input.",
                primary_exception,
            )
            return fernet.decrypt(encrypted_api_key).decode()
    return ""
